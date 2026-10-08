# Antinomie 0.1.0 Workflow Demo

The MP4 is a real native-app screen recording, not a mockup or a generated trace.
It shows VM creation, boot, upload, interactive program execution, saved run
history, decoded file-open flags, captured buffers and retained terminal output.
Idle time and the interval between live recording and archive inspection are cut;
chapter captions are added above the application. There is no audio.

| Setting | Recorded value |
|---|---|
| Application | Release ELF reporting Antinomie 0.1.0, from the main checkout at `5a3fdaef01f09ea29b6049dae787cf770f5180b0` |
| Executable SHA-256 | `14e87c40fd764d8159a704fa24f2c78dcea6ed936db92f1ac65e2bbe40efb343` |
| Guest | BusyBox, patched Linux 6.12.94, guest contract revision 9 |
| VM | Four vCPUs, 1024 MiB RAM, TCG, networking disconnected |
| Workload | Original harmless shell script; input, file creation/read/copy, directory listing and child-process execution in `/tmp/antinomie-demo` |
| Guest identity | UID/GID 1000 |
| Video | 1440 x 900, 15 fps, H.264 MP4, approximately 96 seconds |
| Isolation | Dedicated X display, application preferences and disposable VM data; no user desktop or existing recordings |

The preview is extracted from the video. The captured run exits with code 0 and
has six tasks in its retained run metadata. It is reopened after the monitor
restarts, with the VM no longer running. This is a workflow demonstration, not a
performance benchmark, complete syscall-coverage claim or containment guarantee.
It does not demonstrate unreleased feature-branch functionality.

Original recording and explanatory text: copyright (c) 2026 MikiMiku
(MoreMorePwn), under the repository's MIT license. Displayed application fonts
and icons retain the terms listed in the root third-party notices.
