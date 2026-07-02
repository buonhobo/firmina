use std::path::PathBuf;

use lopdf::{Object, dictionary};

pub fn test() {
    let mut doc = lopdf::IncrementalDocument::load(PathBuf::from("testpdf.pdf")).unwrap();
    let sig_id = doc.new_document.add_object(dictionary! {
        "Type" => "Sig",
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => "ETSI.CAdES.detached",

        // Fixed-width placeholder so you can patch it later.
        "ByteRange" => vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ],

        // Hex string placeholder.
        "Contents" => Object::String(
            vec![0xDE, 0xAD, 0xBE, 0xEF ]// 4 bytes
                .repeat(4) // 16 bytes
                .repeat(1024) // 16KiB
            ,
            lopdf::StringFormat::Literal,
        ),
    });
    let root_id = doc
        .get_prev_documents()
        .trailer
        .get(b"Root")
        .unwrap()
        .as_reference()
        .unwrap();

    doc.opt_clone_object_to_new_document(root_id);

    let root = doc
        .new_document
        .get_object_mut(root_id)
        .unwrap()
        .as_dict_mut()
        .unwrap();

    root.set("DebugSig", sig_id);
    doc.save(PathBuf::from("testpdf2.pdf")).unwrap();
}
