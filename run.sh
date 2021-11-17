#!/bin/sh
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip /stuff/perso/target/debug/perso
cargo run