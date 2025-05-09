const socket = io("http://localhost:5000");
const passphrase = "this-is-a-shared-secret-key";

function getKey() {
    return CryptoJS.SHA256(passphrase);
}

function encryptMessage(message) {
    const key = getKey();
    const encrypted = CryptoJS.AES.encrypt(message, key.toString());
    return encrypted.toString();
}

function decryptMessage(cipherText) {
    const key = getKey();
    const bytes = CryptoJS.AES.decrypt(cipherText, key.toString());
    return bytes.toString(CryptoJS.enc.Utf8);
}

function sendMessage() {
    const msg = document.getElementById("msg").value;
    const encrypted = encryptMessage(msg);
    socket.emit("chat", encrypted);
    document.getElementById("msg").value = "";
}

socket.on("chat", function (data) {
    const decrypted = decryptMessage(data);
    console.log("Decrypted on frontend:", decrypted);
    const li = document.createElement("li");
    li.textContent = decrypted || "[DECRYPTION FAILED]";
    document.getElementById("chat").appendChild(li);
});
