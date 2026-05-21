import Modal from '@typo3/backend/modal.js';

class AttackModal {

    constructor() {
        this.initialized = false;
        this.init();
    }

    init() {
        // MutationObserver, wartet bis #attack-list im DOM ist
        const observer = new MutationObserver(() => {
            const table = document.querySelector('#attack-list');
            if (table && !this.initialized) {
                this.initialized = true;
                this.detailBtns = table.querySelectorAll('.detailBtn');
                this.bindEvents();
            }
        });

        observer.observe(document.body, { childList: true, subtree: true });

        // Optional: falls Tabelle schon da ist
        const table = document.querySelector('#attack-list');
        if (table) {
            this.initialized = true;
            this.detailBtns = table.querySelectorAll('.detailBtn');
            this.bindEvents();
        }
    }

    bindEvents() {
        if (!this.detailBtns || this.detailBtns.length === 0) return;

        this.detailBtns.forEach(button => {
            button.addEventListener('click', () => {
                const uid = button.dataset.uid;
                const hiddenField = document.getElementById(`details-${uid}`);
                const raw = hiddenField ? hiddenField.innerHTML : '<p>Keine Details verfügbar.</p>';
                const sanitized = this.sanitizeHTML(raw);
                const contentElement = document.createElement('div');
                contentElement.innerHTML = sanitized;
                Modal.advanced({
                    title:'Details',
                    content:contentElement,
                    size:Modal.sizes.large,
                    staticBackdrop:false,
                });
            });
        });
    }

    sanitizeHTML(dirty) {
        dirty = atob(dirty);
        return dirty.replace(/<script([^>]*)>([\S\s]*?)<\/script>/gmi, function(match, p1, p2) {
            return '&lt;script' + p1 + '&gt;' + p2 + '&lt;/script&gt;';
        });
    }
}

// Export als TYPO3 Module
export default new AttackModal();
