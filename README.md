# Userspace bpf filter

## build

### Environment
```bash
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/userland/nbpf
./configure
make
mkdir -p /usr/lib/nbpf
cp libnbpf.a /usr/lib/nbpf
```
