document.addEventListener("DOMContentLoaded", () => {
  // --- 1. Toggle visibilité mot de passe ---
  const toggleIcons = document.querySelectorAll(".toggle-password");
  toggleIcons.forEach(icon => {
    icon.addEventListener("click", () => {
      const input = icon.previousElementSibling;
      if (input.type === "password") {
        input.type = "text";
        icon.innerHTML = "🙈";
      } else {
        input.type = "password";
        icon.innerHTML = "👁️";
      }
    });
  });

  // --- 2. Vérification email ---
  const emailInputs = document.querySelectorAll("input[type='email']");
  emailInputs.forEach(input => {
    input.addEventListener("input", () => {
      if (!input.validity.valid) {
        input.classList.add("invalid");
      } else {
        input.classList.remove("invalid");
      }
    });
  });

  // --- 3. Vérification mot de passe fort (page inscription + reset) ---
  const password = document.querySelector("#password");
  const confirmPassword = document.querySelector("#confirm_password");
  if (password && confirmPassword) {
    confirmPassword.addEventListener("input", () => {
      if (confirmPassword.value !== password.value) {
        confirmPassword.setCustomValidity("Les mots de passe ne correspondent pas");
      } else {
        confirmPassword.setCustomValidity("");
      }
    });
  }
});
