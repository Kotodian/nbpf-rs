fn main() {
    println!("cargo:rustc-link-search=native=/usr/lib/nbpf");
    println!("cargo:rustc-link-lib=static=nbpf");
}
