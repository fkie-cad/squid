use std::collections::HashMap;

#[derive(PartialEq, Debug)]
pub enum OptVal {
    None,
    Required,
    Optional,
}

#[derive(Debug, PartialEq, Hash, Eq, Clone)]
pub enum OptName<'a> {
    Short(char),
    Long(&'a str),
}

pub trait OptNameConverter<'a> {
    fn as_optname(&self) -> OptName<'a>;
}

impl<'a> OptNameConverter<'a> for char {
    fn as_optname(&self) -> OptName<'a> {
        OptName::Short(*self)
    }
}

impl<'a> OptNameConverter<'a> for &'a str {
    fn as_optname(&self) -> OptName<'a> {
        if self.len() == 1 {
            OptName::Short(self.as_bytes()[0] as char)
        } else {
            OptName::Long(self)
        }
    }
}

struct Opt<'a> {
    name: OptName<'a>,
    val: OptVal,
    default: Option<&'a str>,
}

pub struct GetoptParser<'a> {
    args: Vec<Opt<'a>>,
}

impl<'a> GetoptParser<'a> {
    pub fn new() -> Self {
        Self {
            args: Vec::new(),
        }
    }

    pub fn long(mut self, name: &'a str, val: OptVal, default: Option<&'a str>) -> Self {
        self.args.push(Opt {
            name: OptName::Long(name),
            val,
            default,
        });
        self
    }

    pub fn short(mut self, name: char, val: OptVal, default: Option<&'a str>) -> Self {
        self.args.push(Opt {
            name: OptName::Short(name),
            val,
            default,
        });
        self
    }

    pub fn optstring(mut self, options: &'a str) -> Self {
        let options = options.as_bytes();
        let mut i = 0;

        match options.get(i).copied() {
            Some(b'-') | Some(b'+') => {
                i += 1;
            },
            _ => {},
        }

        while i < options.len() {
            let name = options[i] as char;
            let val = if i + 2 < options.len() && options[i + 1] == b':' && options[i + 2] == b':' {
                i += 2;
                OptVal::Optional
            } else if i + 1 < options.len() && options[i + 1] == b':' {
                i += 1;
                OptVal::Required
            } else {
                OptVal::None
            };

            self.args.push(Opt {
                name: OptName::Short(name),
                val,
                default: None,
            });

            i += 1;
        }

        self
    }

    fn get_long_opt(&self, name: &str) -> Result<&Opt, String> {
        for opt in &self.args {
            if let OptName::Long(optname) = opt.name {
                if optname == name {
                    return Ok(opt);
                }
            }
        }

        Err(format!("Unexpected long argument: {name}"))
    }

    fn get_short_opt(&self, name: char) -> Result<&Opt, String> {
        for opt in &self.args {
            if let OptName::Short(optname) = opt.name {
                if optname == name {
                    return Ok(opt);
                }
            }
        }

        Err(format!("Unexpected short argument: {name}"))
    }

    fn parse<S: AsRef<str> + 'a>(&self, args: &'a [S], long_only: bool) -> Result<ArgList<'a>, String> {
        let mut positionals = Vec::new();
        let mut opts = HashMap::new();
        let mut idx = 1;

        for opt in &self.args {
            if let Some(default) = opt.default {
                opts.insert(opt.name.clone(), Some(default));
            }
        }

        while idx < args.len() {
            let arg = args[idx].as_ref();

            if arg == "--" {
                for arg in &args[idx + 1..] {
                    positionals.push(arg.as_ref());
                }

                break;
            } else if arg == "-" {
                positionals.push(arg);
            } else if arg.starts_with('@') {
                return Err(format!("Reading args from file {arg} is not supported"));
            } else if let Some(arg) = arg.strip_prefix("--") {
                if let Some((name, val)) = arg.split_once('=') {
                    // --<arg>[=<value>]
                    match self.get_long_opt(name)?.val {
                        OptVal::Required | OptVal::Optional => {},
                        OptVal::None => {
                            return Err(format!("Supplied a value for argument {name} where none was expected"));
                        },
                    }

                    opts.insert(name.as_optname(), Some(val));
                } else {
                    // --<arg> [<value>]
                    match self.get_long_opt(arg)?.val {
                        OptVal::Required => {
                            idx += 1;

                            if idx >= args.len() {
                                return Err(format!("No value supplied for option {arg}"));
                            }

                            opts.insert(arg.as_optname(), Some(args[idx].as_ref()));
                        },
                        OptVal::Optional => {
                            // If the value of a long option is optional it
                            // MUST be supplied via --<arg>=<value>.
                            // Thus the current arg has no value.
                            opts.entry(arg.as_optname()).or_insert(None);
                        },
                        OptVal::None => {
                            opts.insert(arg.as_optname(), None);
                        },
                    }
                }
            } else if let Some(arg) = arg.strip_prefix('-') {
                let mut parse_short = true;

                if long_only {
                    if let Some((name, val)) = arg.split_once('=') {
                        // -<arg>[=<value>]
                        if let Ok(opt) = self.get_long_opt(name) {
                            match opt.val {
                                OptVal::Required | OptVal::Optional => {},
                                OptVal::None => {
                                    return Err(format!("Supplied a value for argument {name} where none was expected"));
                                },
                            }

                            opts.insert(name.as_optname(), Some(val));
                            parse_short = false;
                        }
                    } else if let Ok(opt) = self.get_long_opt(arg) {
                        // -<arg> [<value>]
                        match opt.val {
                            OptVal::Required => {
                                idx += 1;

                                if idx >= args.len() {
                                    return Err(format!("No value supplied for option {arg}"));
                                }

                                opts.insert(arg.as_optname(), Some(args[idx].as_ref()));
                            },
                            OptVal::Optional => {
                                // If the value of a long option is optional it
                                // MUST be supplied via -<arg>=<value>.
                                // Thus the current arg has no value.
                                opts.entry(arg.as_optname()).or_insert(None);
                            },
                            OptVal::None => {
                                opts.insert(arg.as_optname(), None);
                            },
                        }

                        parse_short = false;
                    }
                }

                if parse_short {
                    let arg = arg.as_bytes();
                    let mut subidx = 0;

                    while subidx < arg.len() {
                        let name = arg[subidx] as char;

                        match self.get_short_opt(name)?.val {
                            OptVal::None => {
                                opts.insert(name.as_optname(), None);
                            },
                            OptVal::Required => {
                                subidx += 1;

                                if subidx >= arg.len() {
                                    idx += 1;

                                    if idx >= args.len() {
                                        return Err(format!("No value specified after short option {name}"));
                                    }

                                    opts.insert(name.as_optname(), Some(args[idx].as_ref()));
                                } else {
                                    let value = std::str::from_utf8(&arg[subidx..]).unwrap();
                                    opts.insert(name.as_optname(), Some(value));
                                }

                                break;
                            },
                            OptVal::Optional => {
                                subidx += 1;

                                if subidx >= arg.len() {
                                    opts.entry(name.as_optname()).or_insert(None);
                                } else {
                                    let value = std::str::from_utf8(&arg[subidx..]).unwrap();
                                    opts.insert(name.as_optname(), Some(value));
                                }

                                break;
                            },
                        }

                        subidx += 1;
                    }
                }
            } else {
                positionals.push(arg);
            }

            idx += 1;
        }

        Ok(ArgList {
            opts,
            positionals,
        })
    }

    pub fn parse_long_only<S: AsRef<str> + 'a>(&self, args: &'a [S]) -> Result<ArgList<'a>, String> {
        self.parse(args, true)
    }

    pub fn parse_long<S: AsRef<str> + 'a>(&self, args: &'a [S]) -> Result<ArgList<'a>, String> {
        self.parse(args, false)
    }
}

#[derive(Debug)]
pub struct ArgList<'a> {
    opts: HashMap<OptName<'a>, Option<&'a str>>,
    positionals: Vec<&'a str>,
}

impl<'a> ArgList<'a> {
    pub fn arg_present<T: OptNameConverter<'a>>(&self, name: T) -> bool {
        self.opts.contains_key(&name.as_optname())
    }

    /// For arguments that are [`OptVal::Required`] get the value of the option.
    /// If the argument is not present return [`None`].
    pub fn arg_value<T: OptNameConverter<'a>>(&self, name: T) -> Option<&'a str> {
        self.opts.get(&name.as_optname()).map(|x| x.unwrap())
    }

    pub fn positionals(&self) -> &[&'a str] {
        &self.positionals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser1() {
        let parser =
            GetoptParser::new().long("long-value", OptVal::Required, None).long("long", OptVal::None, None).optstring("wxyzo:").short('p', OptVal::Optional, Some("p-value"));

        let args = parser.parse_long_only(&["progname", "-", "--long-value=value", "pos2", "-long", "pos3", "-xyzovalue", "-p", "pos4"]).unwrap();
        println!("{:#?}", args);
        assert_eq!(args.arg_value("long-value"), Some("value"));
        assert!(args.arg_present("long"));
        assert!(args.arg_present('x'));
        assert!(!args.arg_present("w"));

        let args = parser.parse_long_only(&["progname", "-long-value", "value", "-o", "value", "-x", "positional", "-pvalue", "--", "-y", "-z"]).unwrap();
        println!("{:#?}", args);
        assert!(!args.arg_present("long"));
    }

    #[test]
    fn test_parser2() {
        let parser = GetoptParser::new().optstring("ab:c::d");

        let args = parser.parse_long_only(&["progname", "-abvalue", "-c", "-d"]).unwrap();
        println!("{:#?}", args);
    }
}
