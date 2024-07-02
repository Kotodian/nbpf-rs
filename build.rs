fn main() {
    println!("cargo:rustc-lik-search=native=/usr/lib/nbpf");
    println!("cargo:rustc-link-lib=static=nbpf");
}
