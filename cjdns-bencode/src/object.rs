use std::convert::TryFrom;
use std::iter::FromIterator;
use std::ops::{Deref, DerefMut};
use std::borrow::{Borrow, Cow};
use std::collections::BTreeMap;
use std::convert::TryInto;

use eyre::{eyre, Context, Result};

// Traits

pub trait Inner {
    type InnerT: Default;
    fn inner(&self) -> &Self::InnerT;
    fn inner_mut(&mut self) -> &mut Self::InnerT;
    fn into_inner(self) -> Self::InnerT;
}
macro_rules! impl_inner {
    ($a:lifetime, $t:ty, $inner:ty) => {
        impl<$a> Inner for $t {
            type InnerT = $inner;
            fn inner(&self) -> &Self::InnerT {
                &self.0
            }
            fn inner_mut(&mut self) -> &mut Self::InnerT {
                &mut self.0
            }
            fn into_inner(self) -> Self::InnerT {
                self.0
            }
        }
        impl<$a> Deref for $t {
            type Target = <Self as Inner>::InnerT;
            fn deref(&self) -> &Self::Target {
                self.inner()
            }
        }
        impl<$a> DerefMut for $t {
            fn deref_mut(&mut self) -> &mut Self::Target {
                self.inner_mut()
            }
        }
    };
}

pub trait Get<'a> {
    type Key: std::fmt::Display + ?Sized;
    fn try_get_obj(&self, k: &Self::Key) -> Result<Option<&Object<'a>>>;
    fn try_get_obj_mut(&mut self, k: &Self::Key) -> Result<Option<&mut Object<'a>>>;
    fn has(&self, k: &Self::Key) -> bool {
        if let Ok(Some(_)) = self.try_get_obj(k) { true } else { false }
    }
    fn get_obj(&self, index: &Self::Key) -> Result<&Object<'a>> {
        self.try_get_obj(index)?.ok_or_else(||eyre!("Missing entry {index}"))
    }
    fn get_obj_mut(&mut self, index: &Self::Key) -> Result<&mut Object<'a>> {
        self.try_get_obj_mut(index)?.ok_or_else(||eyre!("Missing entry {index}"))
    }
    fn try_get<'b,T>(&'b self, index: &Self::Key) -> Result<Option<T>>
        where T: TryFrom<&'b Object<'a>, Error=eyre::Error>, 'a: 'b
    {
        let Some(obj) = self.try_get_obj(index)? else { return Ok(None) };
        let t: T = obj.try_into()?;
        Ok(Some(t))
    }
    fn try_get_mut<'b,T>(&'b mut self, index: &Self::Key) -> Result<Option<T>>
        where T: TryFrom<&'b mut Object<'a>, Error=eyre::Error>, 'a: 'b
    {
        let Some(obj) = self.try_get_obj_mut(index)? else { return Ok(None) };
        let t: T = obj.try_into()?;
        Ok(Some(t))
    }
    fn get<'b,T>(&'b self, index: &Self::Key) -> Result<T>
        where T: TryFrom<&'b Object<'a>, Error=eyre::Error>, 'a: 'b
    {
        self.try_get(index)?.ok_or_else(||eyre!("Missing entry {index}"))
    }
    fn get_mut<'b,T>(&'b mut self, index: &Self::Key) -> Result<T>
        where T: TryFrom<&'b mut Object<'a>, Error=eyre::Error>, 'a: 'b
    {
        self.try_get_mut(index)?.ok_or_else(||eyre!("Missing entry {index}"))
    }
    fn try_get_bytes<'b>(&'b self, k: &Self::Key) -> Result<Option<&'b[u8]>> where 'a: 'b {
        Ok(self.try_get_bstr(k)?.map(|v|v.into()))
    }
    fn get_bytes<'b>(&'b self, k: &Self::Key) -> Result<&'b [u8]> where 'a: 'b {
        Ok(self.get_bstr(k)?.into())
    }
    fn try_get_str<'b>(&'b self, k: &Self::Key) -> Result<Option<&'b str>> where 'a: 'b {
        self.try_get_bstr(k)?.map(|v|v.try_into()).transpose()
    }
    fn try_get_string<'b>(&'b self, k: &Self::Key) -> Result<Option<String>> where 'a: 'b {
        self.try_get_bstr(k)?.map(|v|v.try_into()).transpose()
    }
    fn get_str<'b>(&'b self, k: &Self::Key) -> Result<&'b str> where 'a: 'b {
        self.get_bstr(k)?.try_into()
    }
    fn get_string<'b>(&'b self, k: &Self::Key) -> Result<String> where 'a: 'b {
        self.get_bstr(k)?.try_into()
    }
    fn try_get_bstr(&self, k: &Self::Key) -> Result<Option<&Bstr<'a>>> { self.try_get(k) }
    fn get_bstr(&self, k: &Self::Key) -> Result<&Bstr<'a>> { self.get(k) }
    fn try_get_int(&self, k: &Self::Key) -> Result<Option<i64>> { self.try_get(k) }
    fn get_int(&self, k: &Self::Key) -> Result<i64> { self.get(k) }
    fn try_get_dict(&self, k: &Self::Key) -> Result<Option<&Dict<'a>>> { self.try_get(k) }
    fn try_get_dict_mut(&mut self, k: &Self::Key) -> Result<Option<&mut Dict<'a>>> { self.try_get_mut(k) }
    fn get_dict(&self, k: &Self::Key) -> Result<&Dict<'a>> { self.get(k) }
    fn get_dict_mut(&mut self, k: &Self::Key) -> Result<&mut Dict<'a>> { self.get_mut(k) }
    fn try_get_list(&self, k: &Self::Key) -> Result<Option<&List<'a>>> { self.try_get(k) }
    fn try_get_list_mut(&mut self, k: &Self::Key) -> Result<Option<&mut List<'a>>> { self.try_get_mut(k) }
    fn get_list(&self, k: &Self::Key) -> Result<&List<'a>> { self.get(k) }
    fn get_list_mut(&mut self, k: &Self::Key) -> Result<&mut List<'a>> { self.get_mut(k) }
}

// Types

#[derive(PartialEq, PartialOrd, Ord, Eq, Clone, Debug)]
pub struct Bstr<'a>(Cow<'a, [u8]>);
impl_inner!('a, Bstr<'a>, Cow<'a, [u8]>);
impl<'a> Bstr<'a> {
    pub fn new(bytes: Cow<'a, [u8]>) -> Self {
        Bstr(bytes)
    }
    pub fn obj(self) -> Object<'a> {
        Object::Bytes(self)
    }
    pub fn into_owned(self) -> Bstr<'static> {
        Bstr(Cow::Owned(self.0.into_owned()))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &*self.0
    }
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&*self.0).context("Unable to parse as utf8")
    }
}
impl<'a> Borrow<[u8]> for Bstr<'a> {
    fn borrow(&self) -> &[u8] {
        self.0.borrow()
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct List<'a>(Vec<Object<'a>>);
impl_inner!('a, List<'a>, Vec<Object<'a>>);
impl<'a> List<'a> {
    pub fn new() -> Self { Self(Default::default()) }
    pub fn obj(self) -> Object<'a> { Object::List(self) }
    pub fn into_owned(self) -> List<'static> {
        List(self.0.into_iter().map(|v|v.into_owned()).collect())
    }
    pub fn push<'b: 'a>(&mut self, value: impl Into<Object<'b>>) {
        self.deref_mut().push(value.into());
    }
    pub fn insert<'b: 'a>(&mut self, index: usize, value: impl Into<Object<'b>>) {
        self.deref_mut().insert(index, value.into());
    }
}
impl<'a> Get<'a> for List<'a> {
    type Key = usize;
    fn try_get_obj(&self, index: &usize) -> Result<Option<&Object<'a>>> {
        Ok(self.0.get(*index))
    }
    fn try_get_obj_mut(&mut self, index: &usize) -> Result<Option<&mut Object<'a>>> {
        Ok(self.0.get_mut(*index))
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Dict<'a>(BTreeMap<Bstr<'a>, Object<'a>>);
impl_inner!('a, Dict<'a>, BTreeMap<Bstr<'a>, Object<'a>>);
impl<'a> Dict<'a> {
    pub fn new() -> Self { Self(Default::default()) }
    pub fn obj(self) -> Object<'a> { Object::Dict(self) }
    pub fn into_owned(self) -> Dict<'static> {
        Dict(self.0.into_iter().map(|(k,v)|{
            (k.into_owned(), v.into_owned())
        }).collect())
    }

    pub fn insert<'b: 'a, 'c:'a>(&mut self, key: impl Into<Bstr<'b>>, value: impl Into<Object<'c>>) {
        self.0.insert(key.into(), value.into());
    }
    pub fn remove(&mut self, key: &str) {
        self.0.remove(key.as_bytes());
    }
}
impl<'a> Get<'a> for Dict<'a> {
    type Key = str;
    fn try_get_obj(&self, k: &Self::Key) -> Result<Option<&Object<'a>>> {
        Ok(self.0.get(k.as_bytes()))
    }
    fn try_get_obj_mut(&mut self, k: &Self::Key) -> Result<Option<&mut Object<'a>>> {
        Ok(self.0.get_mut(k.as_bytes()))
    }
}

/// An owned or borrowed bencoded value.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Object<'a> {
    /// An owned or borrowed byte string
    Bytes(Bstr<'a>),
    /// A dictionary mapping byte strings to values
    Dict(Dict<'a>),
    /// A signed integer
    Integer(i64),
    /// A list of values
    List(List<'a>),
}
impl <'a> Object<'a> {
    pub fn into_owned(self) -> Object<'static> {
        match self {
            Object::Bytes(b) => Object::Bytes(b.into_owned()),
            Object::Integer(i) => Object::Integer(i),
            Object::List(l) => Object::List(l.into_owned()),
            Object::Dict(d) => Object::Dict(d.into_owned()),
        }
    }

    // Bstr
    pub fn as_bstr(&self) -> Result<&Bstr<'a>> { self.try_into() }
    pub fn as_bstr_mut(&mut self) -> Result<&mut Bstr<'a>> { self.try_into() }
    pub fn into_bstr(self) -> Result<Bstr<'a>> { self.try_into() }
    pub fn as_bytes(&self) -> Result<&[u8]> { Ok(self.as_bstr()?.as_bytes()) }
    pub fn as_str(&self) -> Result<&str> { Ok(self.as_bstr()?.as_str()?) }

    // Int
    pub fn as_int(&self) -> Result<i64> { self.try_into() }

    // Dict
    pub fn as_dict(&self) -> Result<&Dict<'a>> { self.try_into() }
    pub fn as_dict_mut(&mut self) -> Result<&mut Dict<'a>> { self.try_into() }
    pub fn into_dict(self) -> Result<Dict<'a>> { self.try_into() }

    // List
    pub fn as_list(&self) -> Result<&List<'a>> { self.try_into() }
    pub fn as_list_mut(&mut self) -> Result<&mut List<'a>> { self.try_into() }
    pub fn into_list(self) -> Result<List<'a>> { self.try_into() }
}


// -----
// From
// -----

macro_rules! to_obj {
    ($a:lifetime, $t:ty, $s:ident => $toobj:expr, $fromobj:pat) => {
        impl<$a> From<$t> for Object<$a> {
            fn from($s: $t) -> Self {
                $toobj
            }
        }
    }
}
macro_rules! from_obj {
    ($a:lifetime, $t:ty, $s:ident => $toobj:expr, $fromobj:pat) => {
        impl<$a> TryFrom<Object<$a>> for $t {
            type Error = eyre::Error;
            fn try_from(obj: Object<$a>) -> Result<Self> {
                match obj {
                    $fromobj => Ok($s),
                    _ => Err(eyre!("Incorrect type"))
                }
            }
        }
        impl<$a,'b> TryFrom<&'b Object<$a>> for &'b $t {
            type Error = eyre::Error;
            fn try_from(obj: &'b Object<$a>) -> Result<Self> {
                match obj {
                    $fromobj => Ok($s),
                    _ => Err(eyre!("Incorrect type"))
                }
            }
        }
        impl<$a,'b> TryFrom<&'b mut Object<$a>> for &'b mut $t {
            type Error = eyre::Error;
            fn try_from(obj: &'b mut Object<$a>) -> Result<Self> {
                match obj {
                    $fromobj => Ok($s),
                    _ => Err(eyre!("Incorrect type"))
                }
            }
        }
    };
}
macro_rules! to_from_obj {
    ($a:lifetime, $t:ty, $s:ident => $toobj:expr, $fromobj:pat) => {
        to_obj!($a, $t, $s => $toobj, $fromobj);
        from_obj!($a, $t, $s => $toobj, $fromobj);
    };
}
to_from_obj!('a, Bstr<'a>, s => Object::Bytes(s), Object::Bytes(s));
to_from_obj!('a, List<'a>, l => Object::List(l), Object::List(l));
to_from_obj!('a, Dict<'a>, d => Object::Dict(d), Object::Dict(d));
// obj->int is a special case
to_obj!('a, i64, i => Object::Integer(i), Object::Integer(i));

macro_rules! obj_from {
    ($t:ty, $toty:ty) => {
        impl From<$t> for Object<'static> {
            fn from(s: $t) -> Self {
                let x: $toty = s.into();
                Object::from(x)
            }
        }
    };
}
macro_rules! from {
    ($t:ty, $toty:ty, $s:ident => $exp:expr) => {
        impl From<$t> for $toty {
            fn from($s: $t) -> Self {
                $exp
            }
        }
        obj_from!($t, $toty);
    };
}
macro_rules! obj_from_a {
    ($a:lifetime, $t:ty, $toty:ty) => {
        impl<$a> From<$t> for Object<$a> {
            fn from(s: $t) -> Self {
                let x: $toty = s.into();
                Object::from(x)
            }
        }
    };
}
macro_rules! from_a {
    ($a:lifetime, $t:ty, $toty:ty, $s:ident => $exp:expr) => {
        impl<$a> From<$t> for $toty {
            fn from($s: $t) -> Self {
                $exp
            }
        }
        obj_from_a!($a, $t, $toty);
    };
}
macro_rules! from_obj {
    ($a:lifetime, $b:lifetime, $t:ty, $intermediate:ty, $x:ident => $exp:expr) => {
        impl<$a,$b> TryFrom<&$b Object<$a>> for $t {
            type Error = eyre::Error;
            fn try_from(obj: &'b Object<$a>) -> Result<Self> {
                let $x: $intermediate = obj.try_into()?;
                $exp
            }
        }
    };
}

// Bstr
from_a!('a, &'a str, Bstr<'a>, s => Bstr(s.as_bytes().into()));
from_a!('a, &'a String, Bstr<'a>, s => Bstr(s.as_bytes().into()));
from!(String, Bstr<'static>, s => Bstr(s.into_bytes().into()));
from!(Vec<u8>, Bstr<'static>, s => Bstr(s.into()));
from_a!('a, &'a[u8], Bstr<'a>, s => Bstr(s.into()));
from_a!('a, Cow<'a, [u8]>, Bstr<'a>, s => Bstr(s.into()));

// From<Bstr>
impl<'a,'b> From<&'b Bstr<'a>> for &'b [u8] {
    fn from(s: &'b Bstr<'a>) -> Self {
        s.as_bytes()
    }
}
from_obj!('a, 'b, &'b[u8], &'b Bstr<'a>, s => Ok(s.as_bytes()));
impl<'a,'b> TryFrom<&'b Bstr<'a>> for &'b str {
    type Error = eyre::Error;
    fn try_from(s: &'b Bstr<'a>) -> Result<Self> {
        s.as_str()
    }
}
from_obj!('a, 'b, &'b str, &'b Bstr<'a>, s => s.as_str());
impl<'a> TryFrom<&Bstr<'a>> for String {
    type Error = eyre::Error;
    fn try_from(s: &Bstr<'a>) -> Result<Self> {
        Ok(s.as_str()?.to_string())
    }
}
from_obj!('a, 'b, String, &'b Bstr<'a>, s => Ok(s.as_str()?.to_string()));

macro_rules! convert_number {
    ($n:expr, $t:ty) => {
        if $n < <$t>::MIN as i64 || $n > <$t>::MAX as i64 {
            Err(eyre!("Number out of range"))
        } else {
            Ok($n as $t)
        }
    };
}

// Int
obj_from!(u8, i64);
obj_from!(u16, i64);
obj_from!(u32, i64);
// obj_from!(u64, i64);
obj_from!(i8, i64);
obj_from!(i16, i64);
obj_from!(i32, i64);
obj_from!(bool, i64);
from_obj!('a, 'b, u8, i64, i => convert_number!(i, u8));
from_obj!('a, 'b, u16, i64, i => convert_number!(i, u16));
from_obj!('a, 'b, u32, i64, i => convert_number!(i, u32));
from_obj!('a, 'b, i8, i64, i => convert_number!(i, i8));
from_obj!('a, 'b, i16, i64, i => convert_number!(i, i16));
from_obj!('a, 'b, i32, i64, i => convert_number!(i, i32));
from_obj!('a, 'b, bool, i64, i => Ok(i != 0));
impl<'a> TryFrom<&Object<'a>> for i64 {
    type Error = eyre::Error;
    fn try_from(obj: &Object<'a>) -> Result<Self> {
        match obj {
            Object::Integer(i) => Ok(*i),
            _ => Err(eyre!("Incorrect type"))
        }
    }
}

// List
impl<'a,X> From<Vec<X>> for List<'a> where X: Into<Object<'a>> {
    fn from(l: Vec<X>) -> Self {
        List(
            l.into_iter()
            .map(|x|x.into())
            .collect::<Vec<_>>()
        )
    }
}
impl<'a,X> From<&[X]> for List<'a> where X: Into<Object<'a>> + Clone {
    fn from(l: &[X]) -> Self {
        List(
            l.iter()
            .cloned()
            .map(|x|x.into())
            .collect::<Vec<_>>()
        )
    }
}
impl<'a,X> FromIterator<X> for List<'a> where X: Into<Object<'a>> {
    fn from_iter<I: IntoIterator<Item=X>>(iter: I) -> Self {
        List(
            iter.into_iter()
            .map(|x|x.into())
            .collect::<Vec<_>>()
        )
    }
}

// Dict
impl<'a,K,V> FromIterator<(K,V)> for Dict<'a> where
    K: Into<Bstr<'a>>,
    V: Into<Object<'a>>,
{
    fn from_iter<I: IntoIterator<Item=(K,V)>>(iter: I) -> Self {
        Dict(
            iter.into_iter()
            .map(|(k,v)|(k.into(),v.into()))
            .collect::<BTreeMap<_,_>>()
        )
    }
}