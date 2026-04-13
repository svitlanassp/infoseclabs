async function process(mode) {
    const pass = document.getElementById('pass').value;
    const fileInput = document.getElementById('file');
    const status = document.getElementById('status');

    if (!pass || fileInput.files.length === 0) return alert("Заповніть всі поля!");

    const formData = new FormData();
    formData.append('password', pass);
    formData.append('file', fileInput.files[0]);

    status.innerText = "Обробка... зачекайте";

    try {
        const response = await fetch(`/api/lab3/${mode}`, { method: 'POST', body: formData });

        if (response.status === 200) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = mode === 'encrypt'
                ? fileInput.files[0].name + ".enc"
                : "decrypted_" + fileInput.files[0].name.replace(".enc", "");
            a.click();
            status.innerText = "Готово! Файл завантажено.";
        } else {
            const err = await response.json();
            alert(err.error || "Помилка сервера");
            status.innerText = "Помилка.";
        }
    } catch (e) {
        alert("З'єднання втрачено");
        status.innerText = "Помилка.";
    }
}