use std::{
    io::{Cursor, Write},
    path::PathBuf,
};

use hex::ToHex;
use lopdf::{Object, dictionary};

use crate::cades::{self, Cades, Signer};

#[derive(Debug, thiserror::Error)]
pub enum PadesError {
    #[error(transparent)]
    Lopdf(#[from] lopdf::Error),
    #[error(transparent)]
    Cades(#[from] cades::CadesError),
}

fn get_unsigned_bytes(input: PathBuf) -> Result<Vec<u8>, PadesError> {
    let mut doc = lopdf::IncrementalDocument::load(input)?;
    let now = chrono::Utc::now();
    let m = now.format("D:%Y%m%d%H%M%SZ").to_string();
    let sig_id = doc.new_document.add_object(dictionary! {
        "Type" => "Sig",
        "Filter" => "Adobe.PPKLite",
        "M" => Object::string_literal(m),
        "SubFilter" => "ETSI.CAdES.detached",

        "ByteRange" => vec![
            Object::Integer(0),
            Object::Integer(9999999999),
            Object::Integer(9999999999),
            Object::Integer(9999999999),
        ],

        "Contents" => Object::String(
            vec![0x0 as u8; 1024 * 4 ],
            lopdf::StringFormat::Hexadecimal,
        ),

    });

    let field_id = doc.new_document.new_object_id();

    let sig_num = match doc
        .get_prev_documents()
        .catalog()?
        .get(b"AcroForm")
        .cloned()
    {
        Ok(Object::Reference(acro_id)) => {
            println!("here");
            doc.opt_clone_object_to_new_document(acro_id)?;
            let fields = doc
                .new_document
                .get_dictionary_mut(acro_id)?
                .get_mut(b"Fields")?
                .as_array_mut()?;
            fields.push(field_id.into());
            fields.len()
        }
        _ => {
            let acro_id = doc.new_document.add_object(dictionary! {
                        "Fields" => vec![field_id.into()],
                        "SigFlags" => 3,
            });
            let catalog_id = doc
                .get_prev_documents()
                .trailer
                .get(b"Root")?
                .as_reference()?;
            doc.opt_clone_object_to_new_document(catalog_id)?;
            doc.new_document.catalog_mut()?.set("AcroForm", acro_id);
            1
        }
    };

    doc.new_document.objects.insert(
        field_id,
        dictionary! {
            "FT" => "Sig",
            "F" => "132",
            "Subtype" => "Widget",
            "T" => Object::string_literal(format!("Signature {sig_num}")),
            "Type" => "Annot",
            "V" => sig_id
        }
        .into(),
    );

    let mut buffer = vec![];
    doc.save_to(&mut buffer)
        .expect("writing to a vec should not fail, unless you're out of memory");
    Ok(buffer)
}

pub fn sign_pdf(input: PathBuf, signer: impl Signer + 'static) -> Result<Vec<u8>, PadesError> {
    let mut buffer = get_unsigned_bytes(input)?;
    let byterange_pattern = "/ByteRange[0 9999999999 9999999999 9999999999]";
    let byterange_pos = buffer
        .windows(byterange_pattern.len())
        .position(|w| w == byterange_pattern.as_bytes())
        .unwrap();

    let placeholder_pattern = "/Contents<";
    let placeholder_lt = placeholder_pattern.len() - 1
        + byterange_pos
        + buffer[byterange_pos..]
            .windows(placeholder_pattern.len())
            .position(|w| w == placeholder_pattern.as_bytes())
            .unwrap();

    let placeholder_gt = placeholder_lt
        + buffer[placeholder_lt..]
            .iter()
            .position(|c| *c == '>' as u8)
            .unwrap();

    let byterange_value = format!(
        "/ByteRange[0 {:010} {:010} {:010}]",
        buffer[..placeholder_lt].len(),
        placeholder_gt + 1,
        buffer[(placeholder_gt + 1)..].len()
    );

    buffer.splice(
        byterange_pos..(byterange_pos + byterange_pattern.len()),
        byterange_value.as_bytes().to_vec(),
    );

    let signed_content: Vec<u8> = buffer[..(placeholder_lt)]
        .iter()
        .chain(buffer[(placeholder_gt + 1)..].iter())
        .cloned()
        .collect();

    let mut signature_content = &mut buffer[(placeholder_lt + 1)..(placeholder_gt)];
    let mut cades = Cades::new(Cursor::new(signed_content));
    cades
        .sign(signer)
        .expect("could not sign cades file using smart card");

    let signature = cades
        .finalize_detached()?
        .encode_hex::<Vec<char>>()
        .into_iter()
        .map(|c| c as u8)
        .collect::<Vec<u8>>();
    signature_content
        .write(&signature)
        .expect("writing to a preallocated vec should not fail");

    Ok(buffer)
}
