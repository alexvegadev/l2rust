pub fn new_request_auth_login(request: Vec<u8>) -> Result<(String, String), String> {
    let user_name = String::from_utf8(request[0..14].to_vec()).unwrap();
    let password = String::from_utf8(request[14..28].to_vec()).unwrap();
    Ok((user_name, password))
}