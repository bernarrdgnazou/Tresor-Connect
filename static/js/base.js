// Changer la couleur du header quand on scroll
document.addEventListener("scroll", () => {
  const header = document.querySelector(".custom-header");
  if (window.scrollY > 50) {
    header.classList.add("scrolled");
  } else {
    header.classList.remove("scrolled");
  }
});
