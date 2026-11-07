// SPDX-License-Identifier: GPL-3.0-only
//! Programs by name, and the words of a command: what the exec rules match on.

/// A program and its arguments, from an argument vector or one command of a shell script.
pub(super) struct Command {
    words: Vec<String>,
}

impl Command {
    pub(super) fn new(words: Vec<&str>) -> Self {
        Self::from_words(&words.into_iter().map(str::to_owned).collect::<Vec<_>>())
    }

    pub(super) fn from_words(words: &[String]) -> Self {
        Self {
            words: words.to_vec(),
        }
    }

    pub(super) fn words(&self) -> &[String] {
        &self.words
    }

    pub(super) fn name(&self) -> &str {
        self.words.first().map_or("", |word| super::ctx::base(word))
    }

    pub(super) fn args(&self) -> &[String] {
        self.words.get(1..).unwrap_or_default()
    }

    pub(super) fn text(&self) -> String {
        self.words.join(" ")
    }

    pub(super) fn has(&self, word: &str) -> bool {
        self.args().iter().any(|arg| arg == word)
    }

    pub(super) fn has_any(&self, words: &[&str]) -> bool {
        words.iter().any(|word| self.has(word))
    }

    /// `first` directly followed by `second`.
    pub(super) fn pair(&self, first: &str, second: &str) -> bool {
        self.args()
            .windows(2)
            .any(|pair| pair[0] == first && pair[1] == second)
    }

    pub(super) fn starts_with_any(&self, prefixes: &[&str]) -> bool {
        self.args()
            .iter()
            .any(|arg| prefixes.iter().any(|prefix| arg.starts_with(prefix)))
    }

    /// Arguments that are not options (a lone `-` is an operand).
    pub(super) fn operands(&self) -> Vec<&str> {
        self.args()
            .iter()
            .map(String::as_str)
            .filter(|arg| *arg == "-" || !arg.starts_with('-'))
            .collect()
    }

    /// Any operand names one of the services, with or without `.service`.
    pub(super) fn services(&self, names: &[&str]) -> bool {
        self.operands().iter().any(|operand| {
            let unit = operand.strip_suffix(".service").unwrap_or(operand);
            names
                .iter()
                .any(|name| unit == *name || unit.starts_with(name))
        })
    }
}

pub(super) fn is_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "dash" | "zsh" | "ash" | "ksh" | "mksh" | "csh" | "tcsh" | "fish" | "rbash"
    )
}

/// The ATT&CK ids of an interpreter or shell, if the name is one.
pub(super) fn interpreter(name: &str) -> Option<&'static [&'static str]> {
    let versioned = |stem: &str| {
        name.strip_prefix(stem).is_some_and(|rest| {
            rest.chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
        })
    };
    if is_shell(name) {
        Some(&["T1059.004", "DET0384"])
    } else if versioned("python") || versioned("pypy") {
        Some(&["T1059.006", "DET0063"])
    } else if matches!(name, "node" | "nodejs") {
        Some(&["T1059.007", "DET0264"])
    } else if matches!(name, "luajit") || versioned("lua") {
        Some(&["T1059.011", "DET0101"])
    } else if matches!(
        name,
        "perl" | "ruby" | "tclsh" | "expect" | "awk" | "gawk" | "mawk" | "nawk"
    ) || versioned("php")
        || versioned("perl")
        || versioned("ruby")
        || versioned("tclsh")
    {
        Some(&["T1059"])
    } else {
        None
    }
}

/// The script a shell runs with `-c`, also through `busybox sh -c`.
pub(super) fn shell_script(cmd: &Command) -> Option<String> {
    let words = cmd.words();
    let start = usize::from(cmd.name() == "busybox");
    let name = super::ctx::base(words.get(start)?);
    if !is_shell(name) {
        return None;
    }
    let position = words.iter().skip(start + 1).position(|arg| {
        arg.starts_with('-')
            && !arg.starts_with("--")
            && arg[1..].chars().all(|c| c.is_ascii_alphabetic())
            && arg.ends_with('c')
    })?;
    words.get(start + 1 + position + 1).cloned()
}

/// Split a script into commands at `;`, `&&`, `||`, `|`, `&` and newlines, and
/// each into words, honouring simple quotes. Leading assignments and wrappers
/// (`sudo`, `nohup`, `env`, `exec`, `time`, `setsid`) are dropped.
pub(super) fn segments(script: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut chars = script.chars().peekable();
    let finish_word = |words: &mut Vec<String>, word: &mut String, started: &mut bool| {
        if *started {
            words.push(std::mem::take(word));
            *started = false;
        }
    };
    while let Some(ch) = chars.next() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {
                word.push(ch);
                started = true;
            }
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    started = true;
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        word.push(next);
                        started = true;
                    }
                }
                ' ' | '\t' => finish_word(&mut words, &mut word, &mut started),
                ';' | '\n' | '|' | '&' | '(' | ')' | '{' | '}' | '`' => {
                    finish_word(&mut words, &mut word, &mut started);
                    if matches!(ch, '|' | '&') && chars.peek() == Some(&ch) {
                        chars.next();
                    }
                    if !words.is_empty() {
                        commands.push(std::mem::take(&mut words));
                    }
                }
                _ => {
                    word.push(ch);
                    started = true;
                }
            },
        }
    }
    finish_word(&mut words, &mut word, &mut started);
    if !words.is_empty() {
        commands.push(words);
    }
    commands
        .into_iter()
        .filter_map(|mut words| {
            while words.first().is_some_and(|word| {
                (word.contains('=') && !word.starts_with('-') && !word.starts_with('/'))
                    || matches!(
                        super::ctx::base(word),
                        "sudo"
                            | "nohup"
                            | "env"
                            | "exec"
                            | "time"
                            | "setsid"
                            | "nice"
                            | "stdbuf"
                            | "command"
                            | "then"
                            | "do"
                            | "else"
                    )
            }) {
                words.remove(0);
            }
            (!words.is_empty()).then_some(words)
        })
        .collect()
}

/// A pipe whose far end is an interpreter or shell.
pub(super) fn pipes_into_interpreter(lower: &str) -> bool {
    lower.split('|').skip(1).any(|after| {
        let mut words = after
            .split_whitespace()
            .skip_while(|word| matches!(*word, "sudo" | "env" | "exec" | "-E"));
        words
            .next()
            .map(|word| word.trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == '{'))
            .map(super::ctx::base)
            .is_some_and(|name| {
                interpreter(name).is_some()
                    && !matches!(name, "awk" | "gawk" | "mawk" | "nawk" | "expect")
            })
    })
}

/// `find`/`locate` looking for keys, wallets, password files or documents.
pub(super) fn searches_secrets(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        ".pem",
        "id_rsa",
        ".kdbx",
        "wallet.dat",
        ".key",
        "credentials",
        "authorized_keys",
        ".aws",
        "password",
        ".pfx",
        ".p12",
        ".ovpn",
        ".git-credentials",
        "shadow",
        ".ssh",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// `xclip -o`, `xsel -o`, `wl-paste`: reading the clipboard, not filling it.
pub(super) fn reads_clipboard(name: &str, cmd: &Command) -> bool {
    match name {
        "wl-paste" => true,
        "xclip" => cmd.has_any(&["-o", "-out", "-output"]),
        "xsel" => {
            cmd.has_any(&["-o", "--output"])
                || (cmd.has_any(&["-b", "--clipboard"]) && !cmd.has_any(&["-i", "--input"]))
        }
        _ => false,
    }
}

/// Mining pool arguments: a stratum URL or XMRig's donate level.
pub(super) fn mining_arguments(cmd: &Command) -> bool {
    cmd.args().iter().any(|arg| {
        let lower = arg.to_ascii_lowercase();
        lower.starts_with("stratum+tcp://")
            || lower.starts_with("stratum+ssl://")
            || lower.starts_with("stratum+tls")
            || lower.starts_with("--donate-level")
            || lower.starts_with("--randomx")
    }) || (cmd.has("-o")
        && cmd.has("-u")
        && cmd.args().windows(2).any(|pair| {
            pair[0] == "-o"
                && (pair[1].contains("pool")
                    || pair[1].contains("xmr")
                    || pair[1].contains("monero"))
        }))
}
