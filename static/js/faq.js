document.addEventListener("DOMContentLoaded", () => {
  // FAQ accordion
  document.querySelectorAll(".faq-question").forEach(question => {
    question.addEventListener("click", () => {
      const item = question.parentElement;
      item.classList.toggle("active");
    });
  });

  // Formulaire en AJAX (simulation)
  const form = document.getElementById("questionForm");
  const confirmation = document.getElementById("confirmation");

  form.addEventListener("submit", e => {
    e.preventDefault();
    confirmation.style.display = "block";
    form.reset();

    setTimeout(() => {
      confirmation.style.display = "none";
    }, 4000);
  });
});
