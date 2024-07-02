use std::ffi::CString;

use crate::{
    nbpf_free, nbpf_match, nbpf_parse, nbpf_pkt_info_t, nbpf_tree_t, packet_info::PacketInfo,
};

#[derive(Debug)]
pub struct Tree {
    ptr: *mut nbpf_tree_t,
}

unsafe impl Send for Tree {}
unsafe impl Sync for Tree {}

impl Tree {
    pub fn new(filter: &str) -> Self {
        let filter = CString::new(filter).unwrap();
        unsafe {
            let ptr = nbpf_parse(filter.as_ptr(), None);
            Tree { ptr }
        }
    }

    pub fn match_pkt(&self, packet_info: &PacketInfo) -> i32 {
        unsafe {
            nbpf_match(
                self.ptr as *const nbpf_tree_t,
                packet_info.get_ptr() as *const nbpf_pkt_info_t,
            )
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        unsafe {
            nbpf_free(self.ptr);
        }
    }
}
