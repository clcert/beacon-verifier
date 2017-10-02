function generateCommitment() {
    var local_input, commitment_output;

    // Get the value of the local-value-input field
    local_input = document.getElementById("local-value-input").value;

    // "Clean" user input
    var cleaned_local_input = local_input.toLowerCase().replace(/\n/g,"");

    // Generate SHA3_512 of value
    var shaObj = new jsSHA("SHA3-512", "TEXT");
    shaObj.update(cleaned_local_input.toLowerCase());
    var hash = shaObj.getHash("HEX");

    // Get commitment-output object and set his value
    $('#commitment-output').val(hash);
}

function verifySignature() {

}

function generateLinksForExternalValues() {

}