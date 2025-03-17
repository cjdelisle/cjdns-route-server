//! List of remote functions.

use std::{convert::TryFrom, fmt};

use bencode::object::{Dict, Object, Get};
use eyre::{bail, eyre, Context};

/// List of available remote functions.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Funcs(Vec<Func>);

/// Remote function description.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Func {
    /// Function name.
    pub name: String,
    /// Function argument descriptions.
    pub args: Args,
}

/// Remote function arguments description.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Args(Vec<Arg>);

/// Remote function argument description.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Arg {
    /// Argument name.
    pub name: String,
    /// Required argument flag.
    pub required: bool,
    /// Argument type.
    pub typ: ArgType,
}

/// Remote function argument type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ArgType {
    /// Integer.
    Int,
    /// String.
    String,
    /// List.
    List,
    /// Dictionary.
    Dict,
}

impl Funcs {
    #[inline]
    pub(super) fn new() -> Self {
        Funcs(Vec::new())
    }

    pub(super) fn add_funcs(&mut self, fns: &Dict<'_>) -> eyre::Result<()> {
        let Funcs(list) = self;
        for (fn_name, fn_descr) in fns.iter() {
            let func = Self::parse_fn(
                String::from_utf8(fn_name.to_vec())?,
                fn_descr.clone())?;
            list.push(func);
        }
        list.sort_by(|a, b| String::cmp(&a.name, &b.name));
        Ok(())
    }

    fn parse_fn(fn_name: String, fn_args: Object<'_>) -> eyre::Result<Func> {
        // RemoteFnArgsDescr
        let dict = fn_args.as_dict()?;
        let mut args = Vec::with_capacity(dict.len());
        for (arg_name, arg_descr) in dict.iter() {
            let arg_name = String::from_utf8(arg_name.to_vec())?;
            let arg_desc = arg_descr.as_dict()?;
            let arg_type = arg_desc.try_get_str("type")?
                .ok_or_else(|| eyre!("Missing arg type in argument {arg_name}"))?;
            let typ = ArgType::try_from(arg_type).with_context(||
                format!("Function {} argument {}: invalid type {}", fn_name, arg_name, arg_type))?;
            let required = arg_desc.try_get_int("required")?
                .ok_or_else(|| eyre!("Missing arg required in argument {arg_name}"))?;
            let arg = Arg {
                name: arg_name,
                required: required != 0,
                typ,
            };
            args.push(arg);
        }
        args.sort_by(|a, b| bool::cmp(&a.required, &b.required).reverse().then(String::cmp(&a.name, &b.name)));

        Ok(Func {
            name: fn_name,
            args: Args(args),
        })
    }

    /// Iterator over functions in this list returned in alphabetical order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Func> {
        let Funcs(list) = self;
        list.iter()
    }

    /// Find function by name.
    #[inline]
    pub fn find(&self, name: &str) -> Option<&Func> {
        let Funcs(list) = self;
        list.iter().find(|&f| f.name == name)
    }
}

impl Args {
    /// Iterator over arguments in this list.
    /// Returns required args first in alphabetical order, then non-required in alphabetical order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Arg> {
        let Args(list) = self;
        list.iter()
    }
}

impl TryFrom<&str> for ArgType {
    type Error = eyre::Report;
    fn try_from(s: &str) -> eyre::Result<Self> {
        Ok(match s {
            "Int" => Self::Int,
            "String" => Self::String,
            "List" => Self::List,
            "Dict" => Self::Dict,
            x => bail!("Unknown arg type {}", x)
        })
    }
}

impl fmt::Display for Funcs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Funcs(list) = self;
        for func in list {
            writeln!(f, "{}", func)?;
        }
        Ok(())
    }
}

impl fmt::Display for Func {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}({})", self.name, self.args)
    }
}

impl fmt::Display for Args {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Args(list) = self;
        let args: Vec<String> = list.iter().map(Arg::to_string).collect();
        write!(f, "{}", args.join(", "))
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.required {
            write!(f, "required ")?;
        }
        write!(f, "{} {}", self.typ, self.name)
    }
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}