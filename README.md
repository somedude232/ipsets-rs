# ipsets-rs
ipsets-rs is a Rust library that struct-ifies ipsets and exposes methods for manipulating them in Rust code.

**NOTE**: This library is in very early development. You probably shouldn't use this in production.

## Requirements
### Language Version
* Tested on Rust 1.18.0 on x86_64-unknown-linux-gnu (CentOS 7)

### Packages
* `ipset >= 6.19` (Not tested below this version)

### Crates
* `regex >= 0.2`

### Permissions
* `ipset` requires that you run commands with `root` privileges.

## Installing from cargo
* Coming soon! (Once the crate is published on crates.io)
## Installing and compiling from source
### Getting Requirements
* `sudo dnf install ipset` or `sudo yum install ipset` (CentOS/RHEL/Fedora)
* `sudo apt-get install ipset` (Debian-based, Ubuntu)

### Cloning the repo
* `cd ~/my-git-or-rust-workspace/`
* `git clone https://github.com/somedude232/ipsets-rs/`

## Usage
Insert the following into your `Cargo.toml`:
* `ipsets = "0.1"` (Once on crates.io) **OR**
* `ipsets = { path="/home/user/my-git-or-rust-workspace/ipsets-rs/" }`

And make sure to import it at the top of your Rust files: `extern crate ipsets;`

Full code documentation coming soon.

A basic example:
```
extern crate ipsets;

use std::net::Ipv4Addr;

use ipsets::{Ipset, SetKeyType, SetEntryType, CreateOpts};

fn main() {
    let create_opts = vec![CreateOpts::Timeout(3600)];
    let ipset = Ipset::new(String::from_str("ipsets-rs-test").unwrap(),SetKeyType::Hash,SetEntry::IP(Ipv4Addr::new(0,0,0,0)),create_opts);
    ipset.create();
    ipset.add(SetEntry::IP(Ipv4Addr::new(192.168.1.1)));
    ipset.add(SetEntry::IP(Ipv4Addr::new(10.0.0.1)));
    let contents: Vec<SetEntry> = ipset.list();
    
    for element in contents.iter() {
      println!("{}",element);
    }
    ipset.destroy();
}
```
