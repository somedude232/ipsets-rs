extern crate regex;
extern crate netdefs;

use std::ascii::AsciiExt;
use std::borrow::Borrow;
use std::clone::Clone;
use std::fmt;
use std::error::Error;
use std::net::Ipv4Addr;
use std::process::{Command,Output};
use std::str::FromStr;

use netdefs::layer2::ethernet::MAC_Address;
use regex::{Captures,Regex};

// Should already be on your $PATH, change if not.
static IPSET_BIN_PATH: &str = "ipset";

#[derive(Clone)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

impl fmt::Debug for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TransportProtocol::TCP => write!(f,"tcp"),
            TransportProtocol::UDP => write!(f,"udp"),
        }
    }
}

#[derive(Clone)]
pub enum CreateOpt {
    IPRange(Ipv4Addr, Ipv4Addr),
    PortRange(Port, Port),
    Netmask(u8),
    Timeout(u32),
    Counters,
    HashSize(u32),
    MaxElem(u32),
    FamilyIsIpv4(bool),
    NoMatch,
    ForceAdd,
}

#[derive(Clone)]
pub enum EntryOpt {
    Timeout(u32),
    Packets(u64),
    Bytes(u64),
    Comment(String),
}

#[derive(Clone,Debug)]
pub enum SetKeyType {
    Bitmap,
    Hash,
    List,
}

#[derive(Clone)]
pub enum SetEntry {
    IPRange(Ipv4Addr,Ipv4Addr),
    IP(Ipv4Addr),
    IP_MAC(Ipv4Addr,MAC_Address),
    Port(Port),
    PortRange(Port,Port),
    MAC(MAC_Address),
    Net(Net),
    Net_Net(Net,Net),
    IP_Port(Ipv4Addr,Port),
    Net_Port(Net,Port),
    IP_Port_IP(Ipv4Addr,Port,Ipv4Addr),
    IP_Port_Net(Ipv4Addr,Port,Net),
    IP_Mark(Ipv4Addr,u32),
    Net_Port_Net(Net,Port,Net),
    Net_Iface(Net,String),
    Set(String)
}

impl fmt::Display for SetKeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result = format!("{:?}",self).to_ascii_lowercase();
        write!(f,"{}",result)
    }
}

impl fmt::Display for SetEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result: String = match *self {
            SetEntry::IPRange(ref a, ref b) => format!("{}-{}",a,b),
            SetEntry::PortRange(ref a, ref b) =>  format!("{}-{}",a,b),
            SetEntry::IP(ref a) => format!("{}",a),
            SetEntry::Port(ref a) => format!("{}",a),
            SetEntry::MAC(ref a) => format!("{}",a),
            SetEntry::Net(ref a) => format!("{}",a),
            SetEntry::IP_MAC(ref a, ref b) => format!("{},{}",a,b),
            SetEntry::Net_Net(ref a, ref b) => format!("{},{}",a,b),
            SetEntry::IP_Mark(ref a, ref b) => format!("{},{}",a,b),
            SetEntry::IP_Port(ref a, ref b) => format!("{},{}",a,b),
            SetEntry::Net_Port(ref a, ref b) => format!("{},{}",a,b),
            SetEntry::IP_Port_IP(ref a, ref b, ref c) => format!("{},{},{}",a,b,c),
            SetEntry::IP_Port_Net(ref a, ref b, ref c) => format!("{},{},{}",a,b,c),
            SetEntry::Net_Port_Net(ref a, ref b, ref c) => format!("{},{},{}",a,b,c),
            SetEntry::Set(ref a) => format!("{}",sanitize_input(a)),
            SetEntry::Net_Iface(ref a, ref b) => format!("{},{}",a,sanitize_input(b)),
        };
        write!(f,"{}",result)
    }
}

fn set_entry_to_type_string(se: SetEntry) -> String {
    match se {
        SetEntry::IPRange(_,_) | SetEntry::IP(_) => String::from_str("ip").unwrap(),
        SetEntry::PortRange(_,_) | SetEntry::Port(_) => String::from_str("port").unwrap(),
        SetEntry::MAC(_) => String::from_str("mac").unwrap(),
        SetEntry::Net(_) => String::from_str("net").unwrap(),
        SetEntry::IP_MAC(_,_) => String::from_str("ip,mac").unwrap(),
        SetEntry::Net_Net(_,_) => String::from_str("net,net").unwrap(),
        SetEntry::IP_Mark(_,_) => String::from_str("ip,mark").unwrap(),
        SetEntry::IP_Port(_,_) => String::from_str("ip,port").unwrap(),
        SetEntry::Net_Port(_,_) => String::from_str("net,port").unwrap(),
        SetEntry::IP_Port_IP(_,_,_) => String::from_str("ip,port,ip").unwrap(),
        SetEntry::IP_Port_Net(_,_,_) => String::from_str("ip,port,net").unwrap(),
        SetEntry::Net_Port_Net(_,_,_) => String::from_str("net,port,net").unwrap(),
        SetEntry::Net_Iface(_,_) => String::from_str("net,iface").unwrap(),
        SetEntry::Set(_) => String::from_str("set").unwrap(),
    }
}

impl fmt::Display for CreateOpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result: String = match *self {
            CreateOpt::IPRange(ref a,ref b) => format!("range {}-{}",a,b),
            CreateOpt::PortRange(ref a,ref b) => format!("range {}-{}",a,b),
            CreateOpt::Netmask(ref a) => format!("netmask {}",a),
            CreateOpt::Timeout(ref a) => format!("timeout {}",a),
            CreateOpt::Counters => format!("counters"),
            CreateOpt::HashSize(ref a) => format!("hashsize {}",a),
            CreateOpt::MaxElem(ref a) => format!("maxelem {}",a),
            CreateOpt::FamilyIsIpv4(ref a) => if *a { format!("family inet") } else { format!("family inet6") },
            CreateOpt::NoMatch => format!("nomatch"),
            CreateOpt::ForceAdd => format!("forceadd"),
        };
        write!(f,"{}",result)
    }
}

impl fmt::Display for EntryOpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result: String = match *self {
            EntryOpt::Timeout(ref a) => format!("timeout {}",a),
            EntryOpt::Packets(ref a) => format!("packets {}",a),
            EntryOpt::Bytes(ref a) => format!("bytes {}",a),
            EntryOpt::Comment(ref a) => format!("comment {}",sanitize_input(a)),
        };
        write!(f,"{}",result)
    }
}

pub fn get_regex_for_setentrytype(set_type: SetEntry) -> Regex {
    match set_type {
        SetEntry::IPRange(_,_) => Regex::new(r"((?P<ip1>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})-(?P<ip2>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1}))").unwrap(),
        SetEntry::IP(_) => Regex::new(r"(?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})").unwrap(),
        SetEntry::IP_MAC(_,_) => Regex::new(r"((?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1}),(?P<mac>([a-fA-F0-9]{2}[-:]){5}([a-fA-F0-9]{2}){1}))").unwrap(),
        SetEntry::Port(_) => Regex::new(r"(?P<proto>tcp|udp)|(?P<port>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9])").unwrap(),
        SetEntry::PortRange(_,_) => Regex::new(r"((?P<proto1>tcp|udp):(?P<port1>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9])-(?P<proto2>tcp|udp):(?P<port2>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9]))").unwrap(),
        SetEntry::MAC(_) => Regex::new(r"(?P<mac>([a-fA-F0-9]{2}[-:]){5}([a-fA-F0-9]{2}){1}").unwrap(),
        SetEntry::Net(_) => Regex::new(r"(?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr>3[0-2]|[12]?[0-9])").unwrap(),
        SetEntry::Net_Net(_,_) => Regex::new(r"(?P<ip1>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr1>3[0-2]|[12]?[0-9]),(?P<ip2>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr2>3[0-2]|[12]?[0-9])").unwrap(),
        SetEntry::IP_Port(_,_) => Regex::new(r"(?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1}),(?P<proto>tcp|udp)(?P<port>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9])").unwrap(),
        SetEntry::IP_Port_IP(_,_,_) => Regex::new(r"(?P<ip1>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1}),(?P<proto>tcp|udp)(?P<port>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9])(?P<ip2>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})").unwrap(),
        SetEntry::IP_Port_Net(_,_,_) => Regex::new(r"(?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1}),(?P<proto>tcp|udp)(?P<port>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9]),(?P<netip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr>3[0-2]|[12]?[0-9])").unwrap(),
        SetEntry::IP_Mark(_,_) => Regex::new(r"(?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1}),(?P<mark>0x[0-9a-fA-F]{4})").unwrap(),
        SetEntry::Net_Port(_,_) => Regex::new(r"(?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr>3[0-2]|[12]?[0-9]),(?P<proto>tcp|udp)|(?P<port>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9])").unwrap(),
        SetEntry::Net_Port_Net(_,_,_) => Regex::new(r"(?P<ip1>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr1>3[0-2]|[12]?[0-9]),(?P<proto>tcp|udp):(?P<port>6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5]?[0-9]?[0-9]?[0-9]),(?P<ip2>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr2>3[0-2]|[12]?[0-9])").unwrap(),
        SetEntry::Net_Iface(_,_) => Regex::new(r"(?P<ip>(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9].){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]){1})\/(?p<cidr>3[0-2]|[12]?[0-9]),(?P<iface>[0-9a-zA-Z_\-]{2}?)").unwrap(),
        SetEntry::Set(_) => Regex::new(r"(?P<set>[a-zA-Z0-9\-_]?)").unwrap(),
    }
}

pub fn capture_to_set_entry(entry: Captures, entry_type: SetEntry) -> SetEntry {
    match entry_type {
        SetEntry::IPRange(_,_) => SetEntry::IPRange(Ipv4Addr::from_str(&entry["ip1"]).unwrap(),Ipv4Addr::from_str(&entry["ip2"]).unwrap()),
        SetEntry::IP(_) => SetEntry::IP(Ipv4Addr::from_str(&entry["ip"]).unwrap()),
        SetEntry::IP_MAC(_,_) => SetEntry::IP_MAC(Ipv4Addr::from_str(&entry["ip"]).unwrap(), MAC_Address::from_str(&entry["mac"])),
        SetEntry::Port(_) => SetEntry::Port(Port::new(if &entry["proto"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port"]).unwrap())),
        SetEntry::PortRange(_,_) => SetEntry::PortRange(Port::new(if &entry["proto1"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port1"]).unwrap()),Port::new(if &entry["proto2"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port2"]).unwrap())),
        SetEntry::MAC(_) => SetEntry::MAC(MAC_Address::from_str(&entry["mac"])),
        SetEntry::Net(_) => SetEntry::Net(Net::new(Ipv4Addr::from_str(&entry["ip"]).unwrap(),u8::from_str(&entry["cidr"]).unwrap())),
        SetEntry::Net_Net(_,_) => SetEntry::Net_Net(Net::new(Ipv4Addr::from_str(&entry["ip1"]).unwrap(),u8::from_str(&entry["cidr1"]).unwrap()),Net::new(Ipv4Addr::from_str(&entry["ip2"]).unwrap(),u8::from_str(&entry["cidr2"]).unwrap())),
        SetEntry::IP_Port(_,_) => SetEntry::IP_Port(Ipv4Addr::from_str(&entry["ip"]).unwrap(),Port::new(if &entry["proto"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port"]).unwrap())),
        SetEntry::IP_Port_IP(_,_,_) => SetEntry::IP_Port_IP(Ipv4Addr::from_str(&entry["ip1"]).unwrap(),Port::new(if &entry["proto"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port"]).unwrap()),Ipv4Addr::from_str(&entry["ip2"]).unwrap()),
        SetEntry::IP_Port_Net(_,_,_) => SetEntry::IP_Port_Net(Ipv4Addr::from_str(&entry["ip"]).unwrap(),Port::new(if &entry["proto"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port"]).unwrap()),Net::new(Ipv4Addr::from_str(&entry["netip"]).unwrap(),u8::from_str(&entry["cidr"]).unwrap())),
        SetEntry::IP_Mark(_,_) => SetEntry::IP_Mark(Ipv4Addr::from_str(&entry["ip"]).unwrap(),u32::from_str(&entry["mark"]).unwrap()),
        SetEntry::Net_Port(_,_) => SetEntry::Net_Port(Net::new(Ipv4Addr::from_str(&entry["ip"]).unwrap(),u8::from_str(&entry["cidr"]).unwrap()),Port::new(if &entry["proto"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port"]).unwrap())),
        SetEntry::Net_Port_Net(_,_,_) => SetEntry::Net_Port_Net(Net::new(Ipv4Addr::from_str(&entry["ip1"]).unwrap(),u8::from_str(&entry["cidr1"]).unwrap()),Port::new(if &entry["proto"] == "tcp" {TransportProtocol::TCP} else {TransportProtocol::UDP}, u16::from_str(&entry["port"]).unwrap()),Net::new(Ipv4Addr::from_str(&entry["ip2"]).unwrap(),u8::from_str(&entry["cidr2"]).unwrap())),
        SetEntry::Net_Iface(_,_) => SetEntry::Net_Iface(Net::new(Ipv4Addr::from_str(&entry["ip"]).unwrap(),u8::from_str(&entry["cidr"]).unwrap()),String::from_str(&entry["iface"]).unwrap()),
        SetEntry::Set(_) => SetEntry::Set(String::from_str(&entry["set"]).unwrap()),
    }
}

#[derive(Clone)]
pub struct Port {
    proto: TransportProtocol,
    num: u16,
}

impl Port {
    pub fn new(protocol: TransportProtocol, port_num: u16) -> Port {
        Port {num: port_num, proto: protocol}
    }

    pub fn new_tcp(port_num: u16) -> Port {
        Port { num: port_num, proto: TransportProtocol::TCP }
    }

    pub fn new_udp(port_num: u16) -> Port {
        Port { num: port_num, proto: TransportProtocol::UDP }
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{:?}:{}",self.proto,self.num)
    }
}

#[derive(Clone)]
pub struct Net {
    net_addr: Ipv4Addr,
    cidr: u8,
}

impl Net {
    pub fn new(ip: Ipv4Addr, hot_num: u8) -> Net {
        assert!(hot_num < 33);
        Net { net_addr: ip, cidr: hot_num }
    } 
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}/{}", self.net_addr, self.cidr)
    }
}

pub struct Ipset {
    name: String,
    set_key_type: SetKeyType,
    set_entry_type: SetEntry,
    set_opts: Option<Vec<CreateOpt>>,
}
impl Ipset {
    pub fn new(name: String, set_key_type: SetKeyType, set_entry_type: SetEntry, args: Option<Vec<CreateOpt>>) -> Ipset {
        let san_name = sanitize_input(&name);
        Ipset { name: san_name, set_key_type: set_key_type, set_entry_type: set_entry_type, set_opts: args}
    }
    pub fn create(&self) -> Result<String,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("create").unwrap());
        params.push(self.name.clone());
        params.push(format!("{}:{}",self.set_key_type.to_string(),set_entry_to_type_string(self.set_entry_type.clone())));
        if self.set_opts.clone().is_some() {
            for set_opt in self.set_opts.clone().unwrap().iter() {
                params.push(set_opt.to_string())
            }
        }
        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset create command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            return Ok(stdout);
        }
    }
    pub fn destroy(&self) -> Result<String,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("destroy").unwrap());
        params.push(self.name.clone());

        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset delete command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            return Ok(stdout);
        }
    }
    pub fn list(&self) -> Result<Vec<SetEntry>,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("list").unwrap());
        params.push(self.name.clone());
        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset list command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {            
            let re = get_regex_for_setentrytype(self.set_entry_type.clone());
            let captures = re.captures_iter(&*stdout);
            let mut result: Vec<SetEntry> = Vec::new();
            for cap in captures {
                result.push(capture_to_set_entry(cap,self.set_entry_type.clone()));
            }
            return Ok(result);
        }
    }
    pub fn add(&self, entry: SetEntry, entry_opts: Option<Vec<EntryOpt>>) -> Result<String,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("add").unwrap());
        params.push(self.name.clone());
        params.push(entry.to_string());
        if entry_opts.is_some() {
            for opt in entry_opts.unwrap().iter() {
                params.push(opt.to_string());
            }
        }
        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset add command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            return Ok(stdout);
        }
    }
    pub fn delete(&self, entry: SetEntry) -> Result<String,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("delete").unwrap());
        params.push(self.name.clone());
        params.push(entry.to_string());
        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset delete command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            return Ok(stdout);
        }
    }
    pub fn test(&self, entry: SetEntry) -> Result<Option<String>,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("test").unwrap());
        params.push(self.name.clone());
        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset test command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            if stdout.ends_with("is in set foo.") {
                return Ok(Some(stdout));
            } else if stdout.ends_with("is NOT in set foo.") {
                return Ok(Some(stdout));
            } else {
                println!("Oh shit. What did you do?");
                return Ok(None);
            }
        }
    }
    pub fn save(&self) -> Result<String,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("save").unwrap());
        params.push(self.name.clone());
        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset save command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            return Ok(stdout);
        }
    }
    pub fn flush(&self) -> Result<String,Box<IpsetError>> {
        let mut params: Vec<String> = Vec::new();
        params.push(String::from_str("flush").unwrap());
        params.push(self.name.clone());

        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset flush command");
        
        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            return Ok(stdout);
        }
    }
    pub fn rename(&mut self, new_name: String) -> Result<String,Box<IpsetError>> {
        let san_name = sanitize_input(&new_name);
        let name_clone = self.name.clone();
        
        let mut params: Vec<&str> = Vec::new();
        params.push("rename");
        params.push(&name_clone);
        params.push(&san_name);
        
        let output = Command::new(IPSET_BIN_PATH).args(&params).output().expect("Error executing ipset rename command");

        let stdout = String::from_utf8(output.clone().stdout).unwrap();
        let stderr = String::from_utf8(output.clone().stderr).unwrap();
        if &stderr != "" || !output.status.success() {
            return Err(Box::new(IpsetCommandExecuteError(self.name.clone(), params.join(" "), output)));
        } else {
            self.name = new_name;
            return Ok(stdout);
        }
    } 
}
pub trait IpsetError: Error + fmt::Display {
    fn get_ipset_name(&self) -> &String;
    fn get_params(&self) -> &String;
    fn get_output(&self) -> &Output;
}

#[derive(Debug)]
pub struct IpsetCommandExecuteError(pub String, pub String, pub Output);

impl IpsetCommandExecuteError {
    pub fn new(ipset_name: String, params: String, output: Output) -> IpsetCommandExecuteError {
        IpsetCommandExecuteError(ipset_name,params,output)
    }
}

impl Error for IpsetCommandExecuteError {
    fn description(&self) -> &str {
        "The ipset command terminated with a non-zero exit code and output to STDERR."
    }
}

impl fmt::Display for IpsetCommandExecuteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let stderr = String::from_utf8(self.2.stderr.clone()).unwrap();
        write!(f,"The ipset named \"{}\" failed to run \"ipset {}\". stderr says \"{}\"", self.0, self.1, stderr)
    }
}

impl IpsetError for IpsetCommandExecuteError {
    fn get_ipset_name(&self) -> &String {
        &self.0
    }
    fn get_params(&self) -> &String {
        &self.1
    }
    fn get_output(&self) -> &Output {
        &self.2
    }
}


fn sanitize_input(input: &String) -> String {
    let non_alnum_re = Regex::new(r"([[^_-]&&[[:^alnum:]]])").unwrap();
    String::from_str(&*non_alnum_re.replace_all(&*input,"")).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_entry_to_type_string_test() {
        assert_eq!(set_entry_to_type_string(SetEntry::IPRange(Ipv4Addr::new(0,0,0,0),Ipv4Addr::new(255,255,255,255))),String::from_str("ip").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::IP(Ipv4Addr::new(1,2,3,4))),String::from_str("ip").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::MAC(MAC_Address::from_str("12:34:56:78:90:AB"))),String::from_str("mac").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::Net(Net::new(Ipv4Addr::new(4,3,2,1),13))),String::from_str("net").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::IP_MAC(Ipv4Addr::new(192,168,0,0),MAC_Address::from_str("FE:DC:BA:98:76:54"))),String::from_str("ip,mac").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::Net_Net(Net::new(Ipv4Addr::new(0,0,0,0),0),Net::new(Ipv4Addr::new(192,168,0,0),24))),String::from_str("net,net").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::IP_Port(Ipv4Addr::new(127,0,0,1),Port::new(TransportProtocol::TCP,443))),String::from_str("ip,port").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::Net_Port(Net::new(Ipv4Addr::new(42,52,53,78),32),Port::new(TransportProtocol::UDP,53))),String::from_str("net,port").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::IP_Port_IP(Ipv4Addr::new(54,23,17,69),Port::new(TransportProtocol::TCP,21),Ipv4Addr::new(35,72,214,36))),String::from_str("ip,port,ip").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::IP_Port_Net(Ipv4Addr::new(0,63,127,191),Port::new(TransportProtocol::UDP,23),Net::new(Ipv4Addr::new(10,0,0,0),24))),String::from_str("ip,port,net").unwrap());
        assert_eq!(set_entry_to_type_string(SetEntry::IP_Mark(Ipv4Addr::new(0,0,0,0),0xF00F)),String::from_str("ip,mark").unwrap());

    }

    #[test]
    fn sanitized_input() {
        assert_eq!(sanitize_input(&String::from_str("test~`;:_'\"[]{},.-<>/+=").unwrap()),String::from_str("test_-").unwrap())
    }

    #[test]
    fn create_ipset_no_duplication() {
        let ipset = Ipset::new(String::from_str("ipsets-rs-test").unwrap(),SetKeyType::Hash,SetEntry::IP(Ipv4Addr::new(0,1,2,3)),None);
        let first_result = ipset.create();
        let second_result = ipset.create();
        assert_eq!(first_result.is_ok(),second_result.is_err());
        assert!(first_result.is_ok());
        ipset.destroy();
    }
}
