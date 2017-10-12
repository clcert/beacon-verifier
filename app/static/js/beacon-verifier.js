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
    var record_id, external_json, base_url;

    base_url = "http://localhost:5000";

    // Get the record id that the user wants to get their external events
    record_id = $('#record_id').val();

    // Get external events
    $.ajax({
        // url: base_url + "/beacon/1.0/raw/id/" + record_id,
        url: "http://172.17.69.98:5000/beacon/1.0/raw/id/89",
        type: "GET",
        data: {},
        success: function (json) {
            console.log(json);
        },
        error: function (xhr, status, errorThrown) {
            alert("Value doesn't exist: " + xhr.status + " " + errorThrown + " " + status);
        }
    });

    console.log(external_json);
}