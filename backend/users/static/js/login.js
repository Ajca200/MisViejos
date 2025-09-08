// Elementos principales
const input_email = document.getElementById('email');
const input_password = document.getElementById('password');
const btn_submit = document.getElementById('btn-submit');
const btn_register = document.getElementById('btn-register');

const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// Estado de validaciones
let isEmailValid = false;
let isPasswordValid = false;

// 🔹 Función para mostrar errores
function showError(input, message) {
    let errorSpan = input.parentElement.querySelector(".error-message");
    if (!errorSpan) {
        errorSpan = document.createElement("span");
        errorSpan.classList.add("error-message");
        input.parentElement.appendChild(errorSpan);
    }
    errorSpan.textContent = message;
    input.classList.add("input-error");
}

// 🔹 Función para limpiar errores
function clearError(input) {
    const errorSpan = input.parentElement.querySelector(".error-message");
    if (errorSpan) errorSpan.remove();
    input.classList.remove("input-error");
}

// 🔹 Habilitar o deshabilitar el botón
function toggleSubmit() {
    btn_submit.disabled = !(isEmailValid && isPasswordValid);
}

// 🔹 Validación del email
input_email.addEventListener("input", (e) => {
    const email = e.target.value.trim();

    if (email.length <= 4 || !emailRegex.test(email)) {
        isEmailValid = false;
        showError(input_email, "Ingresa un correo válido (ejemplo@mail.com)");
    } else {
        isEmailValid = true;
        clearError(input_email);
    }
    toggleSubmit();
});

// 🔹 Validación de la contraseña
input_password.addEventListener("input", (e) => {
    const password = e.target.value.trim();

    if (password.length < 6 || password.length > 12) {
        isPasswordValid = false;
        showError(input_password, "La contraseña debe tener entre 6 y 12 caracteres");
    } else {
        isPasswordValid = true;
        clearError(input_password);
    }
    toggleSubmit();
});

// 🔹 Botón para registro
btn_register.addEventListener("click", () => {
    window.location.href = "/users/register";
});
