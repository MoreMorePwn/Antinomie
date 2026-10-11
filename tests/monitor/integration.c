// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
#define _POSIX_C_SOURCE 200809L
#include "host_api.h"
#include "control.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct ant_client *client;
static uint8_t telemetry[262112], response[16352];
static size_t response_len;
static uint64_t packets, entries, exits, fields, copy_faults, content_matches, orphan_matches;

static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { for (int i=0; i<4; i++) p[i] = v >> (i*8); }
static void put64(uint8_t *p, uint64_t v) { for (int i=0; i<8; i++) p[i] = v >> (i*8); }
static uint16_t get16(const uint8_t *p) { return p[0] | (uint16_t)p[1] << 8; }
static uint32_t get32(const uint8_t *p) { uint32_t v=0; for(int i=0;i<4;i++) v |= (uint32_t)p[i] << (i*8); return v; }
static uint64_t get64(const uint8_t *p) { uint64_t v=0; for(int i=0;i<8;i++) v |= (uint64_t)p[i] << (i*8); return v; }
static void header(uint8_t *p, uint32_t flags) { memset(p,0,8); put16(p,1); put16(p+2,8); put32(p+4,flags); }
static uint64_t now_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000; }

static void drain(void)
{
    size_t len;
    int error;
    while (!(error=ant_read(client,telemetry,sizeof(telemetry),&len))) {
        size_t body_offset;
        packets++;
        if (len < 136 || memcmp(telemetry,"ANTT",4) || get32(telemetry+12)!=len ||
            get16(telemetry+4)!=1 ||
            !((get16(telemetry+6)==1 && get16(telemetry+8)==136) ||
              (get16(telemetry+6)==2 && get16(telemetry+8)==144 && len>=144)) ||
            !get64(telemetry+128)) {
            fprintf(stderr,"bad telemetry framing\n"); exit(30);
        }
        body_offset=get16(telemetry+8);
        if (telemetry[99] == 1) { if(telemetry[98]==1) entries++; if(telemetry[98]==2) exits++; }
        if (telemetry[99] == 2) fields++;
        if (telemetry[99] == 3 && len >= body_offset+24 && !memcmp(telemetry+body_offset,"ANTINOMIE-POINTER-CONTENT",24)) content_matches++;
        if (telemetry[99] == 3 && len >= body_offset+12 && !memcmp(telemetry+body_offset,"PROBE-ORPHAN",12)) orphan_matches++;
        if (telemetry[99] == 4 && len == body_offset+32 && get32(telemetry+body_offset+16)==1) copy_faults++;
    }
    if(error!=-EAGAIN) { fprintf(stderr,"telemetry read %d\n",error); exit(31); }
}

static int command(uint32_t opcode, const uint8_t *args, size_t len)
{
    uint64_t id, received, deadline=now_ms()+15000;
    int32_t status;
    int error=ant_command_send(client,opcode,args,len,&id);
    if(error) return error;
    while(now_ms()<deadline) {
        error=ant_poll(client,10);
        if(error<0) return error;
        drain();
        while(!(error=ant_result_read(client,&received,&status,response,sizeof(response),&response_len))) {
            if(received!=id) { fprintf(stderr,"unexpected result id\n"); return -EPROTO; }
            return status;
        }
        if(error!=-EAGAIN) return error;
    }
    return -ETIMEDOUT;
}

static void checked(uint32_t opcode, const uint8_t *args, size_t len)
{
    int error=command(opcode,args,len);
    if(error) { fprintf(stderr,"command %#x failed: %d\n",opcode,error); exit(32); }
}

int main(int argc,char **argv)
{
    struct ant_backing backing;
    struct ant_memory_region mapping;
    struct ant_options options={0};
    struct ant_stats stats;
    uint8_t args[16352], *binary;
    uint64_t upload,session,deadline;
    char output[65536]={0};
    size_t total,out_len=0,offset;
    FILE *file;
    int error;
    const char *path="/tmp/antinomie-probe", *cwd="/tmp", *env="ANT_PROBE=verified";
    if(argc!=3) { fprintf(stderr,"usage: integration RAM_FILE PROBE_BINARY\n"); return 2; }
    backing=(struct ant_backing){argv[1],1024ULL<<20};
    mapping=(struct ant_memory_region){0,backing.size,0,0};
    options.backings=&backing; options.backing_count=1; options.regions=&mapping; options.region_count=1;
    options.ram_size=backing.size; options.bootstrap_gpa=0x30000000; options.host_timeout_ms=1000;
    error=ant_init(&options,&client);
    if(error) { fprintf(stderr,"attach: %d\n",error); return 3; }
    file=fopen(argv[2],"rb"); if(!file) return 4;
    fseek(file,0,SEEK_END); total=ftell(file); rewind(file); binary=malloc(total);
    if(!binary || fread(binary,1,total,file)!=total) return 5;
    fclose(file);
    /* Give ordinary guest init time to mount its persistent root and PTYs. */
    deadline=now_ms()+3000;
    while(now_ms()<deadline) { if(ant_poll(client,10)<0) return 6; drain(); }
    header(args,ANTC_UPLOAD_OVERWRITE|ANTC_UPLOAD_EXECUTABLE);
    put64(args+8,total); put32(args+16,strlen(path)); put32(args+20,0); memcpy(args+24,path,strlen(path));
    checked(ANTC_UPLOAD_BEGIN,args,24+strlen(path)); if(response_len!=8) return 7; upload=get64(response);
    for(offset=0;offset<total;) {
        size_t size=total-offset; if(size>12000) size=12000;
        header(args,0); put64(args+8,upload); put64(args+16,offset); memcpy(args+24,binary+offset,size);
        checked(ANTC_UPLOAD_CHUNK,args,24+size); if(response_len!=8 || get64(response)!=size) return 8;
        offset+=size;
    }
    free(binary); header(args,0); put64(args+8,upload); checked(ANTC_UPLOAD_COMMIT,args,16);
    header(args,0); put32(args+8,1000); put32(args+12,1000); put32(args+16,1); put32(args+20,1);
    put32(args+24,strlen(path)); put32(args+28,strlen(cwd)); offset=32;
    memcpy(args+offset,path,strlen(path)); offset+=strlen(path); memcpy(args+offset,cwd,strlen(cwd)); offset+=strlen(cwd);
    put32(args+offset,strlen(path)); offset+=4; memcpy(args+offset,path,strlen(path)); offset+=strlen(path);
    put32(args+offset,strlen(env)); offset+=4; memcpy(args+offset,env,strlen(env)); offset+=strlen(env);
    checked(ANTC_EXEC,args,offset); if(response_len!=24) return 9; session=get64(response);
    deadline=now_ms()+15000;
    while(now_ms()<deadline && !strstr(output,"PROBE READY")) {
        header(args,0); put64(args+8,session); put32(args+16,8192); put32(args+20,0);
        checked(ANTC_TERMINAL_READ,args,24);
        if(response_len<8 || get32(response+4)!=response_len-8 || out_len+response_len-8>=sizeof(output)) return 22;
        memcpy(output+out_len,response+8,response_len-8); out_len+=response_len-8;
    }
    if(!strstr(output,"PROBE READY")) { fprintf(stderr,"terminal before input: %s\n",output); return 23; }
    header(args,0); put64(args+8,session); memcpy(args+16,"ping\n",5); checked(ANTC_TERMINAL_INPUT,args,21);
    deadline=now_ms()+10000;
    while(now_ms()<deadline && !strstr(output,"PROBE PASS")) {
        header(args,0); put64(args+8,session); put32(args+16,8192); put32(args+20,0);
        checked(ANTC_TERMINAL_READ,args,24);
        if(response_len<8 || get32(response+4)!=response_len-8 || out_len+response_len-8>=sizeof(output)) return 24;
        memcpy(output+out_len,response+8,response_len-8); out_len+=response_len-8;
    }
    header(args,0); checked(ANTC_STATS,args,8);
    if(response_len!=80) return 25;
    printf("{\"packets\":%"PRIu64",\"entries\":%"PRIu64",\"exits\":%"PRIu64",\"fields\":%"PRIu64",\"copy_faults\":%"PRIu64",\"content_matches\":%"PRIu64",\"tasks_created\":%"PRIu64",\"recorder_packets_failed\":%"PRIu64"}\n",packets,entries,exits,fields,copy_faults,content_matches,get64(response+8),get64(response+48));
    ant_get_stats(client,&stats);
    printf("transport dropped=%"PRIu64" attempted=%"PRIu64"\n",stats.dropped,stats.attempted);
    printf("%s",output);
    if(!strstr(output,"PROBE UID=1000 GID=1000 ENV=verified") || !strstr(output,"PROBE-DESCENDANT") || !strstr(output,"PROBE-ORPHAN") || !strstr(output,"PROBE INPUT=ping") || !strstr(output,"PROBE PASS") || !entries || !exits || !content_matches || !copy_faults || !orphan_matches || get64(response+8)<4) return 26;
    header(args,0);
    if(command(ANTC_STOP_RUN,args,8)!=-EINVAL) return 27;
    put64(args+8,0);
    if(command(ANTC_STOP_RUN,args,16)!=-EINVAL) return 28;
    put64(args+8,UINT64_MAX);
    if(command(ANTC_STOP_RUN,args,16)!=-ESRCH) return 29;
    if (stats.abi >= 9) {
        struct ant_resume_report report;
        if (ant_resume_begin(client) || ant_resume_finish(client,10000,&report) ||
            !report.attachment) return 40;
        header(args,0); checked(ANTC_STATS,args,8);
        ant_close(client); client=NULL;
        if (ant_init(&options,&client)) return 41;
        header(args,0); checked(ANTC_STATS,args,8);
        puts("REATTACH PASS");
    }
    header(args,0); checked(ANTC_SHUTDOWN,args,8); ant_close(client);
    puts("INTEGRATION PASS"); return 0;
}
