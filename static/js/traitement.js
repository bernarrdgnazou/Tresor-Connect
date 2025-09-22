/*
* Script d'animation et d'interaction pour la page de traitement.
* Gère les collapses et l'animation d'apparition des éléments.
*/
document.addEventListener('DOMContentLoaded', () => {

    // --- Fonctionnalité 1 : Gestion des collapses imbriqués ---
    // Cible tous les boutons de déploiement des détails
    document.querySelectorAll('.details-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-bs-target');
            const targetEl = document.querySelector(target);

            // Gère l'icône de la flèche
            const icon = btn.querySelector('.fa-chevron-down');
            if (icon) {
                icon.classList.toggle('rotate');
            }
            
            // Logique pour gérer la visibilité de la carte de détails
            // Si le collapse est déjà ouvert
            if (btn.getAttribute('aria-expanded') === 'true') {
                targetEl.style.display = 'none';
                btn.setAttribute('aria-expanded', 'false');
            } else {
                // Ferme toutes les autres sections ouvertes pour un effet de "focus"
                document.querySelectorAll('.details-container .collapse.show').forEach(openCollapse => {
                    if (openCollapse !== targetEl) {
                        openCollapse.style.display = 'none';
                        const openBtn = document.querySelector(`[data-bs-target="#${openCollapse.id}"]`);
                        if (openBtn) {
                             openBtn.setAttribute('aria-expanded', 'false');
                             const openIcon = openBtn.querySelector('.fa-chevron-down');
                             if (openIcon) {
                                openIcon.classList.remove('rotate');
                             }
                        }
                    }
                });

                // Ouvre la section cible
                targetEl.style.display = 'block';
                btn.setAttribute('aria-expanded', 'true');
            }
        });
    });

    // --- Fonctionnalité 2 : Animation "Reveal" au scroll ---
    const revealElements = document.querySelectorAll('.reveal');
    
    // Configure l'observateur pour déclencher l'animation
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            // Si l'élément est dans la zone de vue
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                // Arrête d'observer l'élément une fois l'animation jouée
                observer.unobserve(entry.target);
            }
        });
    }, {
        // La zone de déclenchement (démarre l'animation quand l'élément est à 10% visible)
        threshold: 0.1
    });

    // Observe chaque élément avec la classe 'reveal'
    revealElements.forEach(el => observer.observe(el));
});