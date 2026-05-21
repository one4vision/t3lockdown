import Charts from '@extension14v/t3lockdown/Charts.js';
class TableFilter {
    constructor(tableSelector, paginationSelector, rowsPerPage = 10, maxVisible = 7) {
        this.table = document.querySelector(tableSelector);
        this.tbody = this.table.querySelector("tbody");
        this.pagination = document.querySelector(paginationSelector);

        this.rowsPerPage = rowsPerPage;
        this.maxVisible = maxVisible;
        this.currentPage = 1;
        this.activeYear = null;
        this.activeMonth = null;
        this.activeType = 'all';
        this.activeMethod = 'all';

        // Alle ursprünglichen Zeilen merken
        this.allRows = Array.from(this.tbody.querySelectorAll("tr"));
        this.rows = [...this.allRows];

        this.bindFilterEvents();
        this.displayPage(1);
    }

    bindFilterEvents() {
        const typeSelect = document.querySelector('#filterType');
        const methodSelect = document.querySelector('#filterMethod');
        const yearButtons = document.querySelectorAll('.yearSelect');
        const resetButton = document.querySelector('#resetFilters');

        typeSelect?.addEventListener('change', e => {
            this.activeType = e.target.value;
            this.displayPage(1);
        });

        methodSelect?.addEventListener('change', e => {
            this.activeMethod = e.target.value;
            this.displayPage(1);
        });

        yearButtons.forEach(btn => {
            btn.addEventListener('click', e => {
                yearButtons.forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.activeYear = e.target.dataset.year;
                this.displayPage(1);
            });
        });

        // Reset-Button
        resetButton?.addEventListener('click', () => {
            this.activeType = 'all';
            this.activeMethod = 'all';
            this.activeYear = null;
            this.activeMonth = null;
            if (typeSelect) typeSelect.value = 'all';
            if (methodSelect) methodSelect.value = 'all';
            yearButtons.forEach(b => b.classList.remove('active'));
            Charts.resetColumnColors();
            this.displayPage(1);
        });
    }

    filterRows() {
        this.rows = this.allRows.filter(row => {
            const type = row.dataset.types?.toLowerCase() || '';
            const method = row.dataset.method?.toUpperCase() || '';
            const year = row.dataset.year;
            const month = row.dataset.month;

            const typeMatch = this.activeType === 'all' || type.includes(this.activeType);
            const methodMatch = this.activeMethod === 'all' || method === this.activeMethod;
            const yearMatch = !this.activeYear || year === this.activeYear;
            const monthMatch = !this.activeMonth || month === this.activeMonth;

            return typeMatch && methodMatch && yearMatch && monthMatch;
        });
    }

    filterByYearMonth(y,m) {
        this.activeYear = y ? String(y) : null;
        this.activeMonth = m ? String(m).padStart(2,'0') : null;
        this.displayPage(1);
    }

    displayPage(page) {
        this.filterRows();
        const totalPages = this.getTotalPages();
        this.currentPage = Math.max(1, Math.min(page, totalPages));

        // Zeilen anzeigen/verstecken
        this.allRows.forEach(row => (row.style.display = "none"));
        const start = (this.currentPage - 1) * this.rowsPerPage;
        const end = start + this.rowsPerPage;
        this.rows.slice(start, end).forEach(row => (row.style.display = ""));

        this.renderPagination(totalPages);

        const countField = document.querySelector('#rowAmount');
        if (countField) {
            const total = this.allRows.length;
            const filtered = this.rows.length;
            countField.textContent = `(${filtered} von ${total})`;
        }
    }

    getTotalPages() {
        return Math.ceil(this.rows.length / this.rowsPerPage) || 1;
    }

    renderPagination(totalPages) {
        if (!this.pagination) return;
        this.pagination.innerHTML = "";

        const createPageItem = (label, page, disabled = false, active = false, ariaLabel = null) => {
            const li = document.createElement("li");
            li.className = `page-item ${disabled ? "disabled" : ""} ${active ? "active" : ""}`;

            const a = document.createElement("a");
            a.className = "page-link";
            a.href = "#";
            a.textContent = label;
            if (ariaLabel) a.setAttribute('aria-label', ariaLabel);
            if (active) a.setAttribute('aria-current', 'page');

            a.onclick = e => {
                e.preventDefault();
                if (!disabled && !active) this.displayPage(page);
            };

            li.appendChild(a);
            return li;
        };

        // "Previous"
        this.pagination.appendChild(
            createPageItem("«", this.currentPage - 1, this.currentPage === 1, false, "Vorherige Seite")
        );

        // Seitenzahlen mit Ellipsen
        let startPage = Math.max(1, this.currentPage - 2);
        let endPage = Math.min(totalPages, startPage + this.maxVisible - 1);

        if (endPage - startPage < this.maxVisible - 1) {
            startPage = Math.max(1, endPage - this.maxVisible + 1);
        }

        if (startPage > 1) {
            this.pagination.appendChild(createPageItem("1", 1));
            if (startPage > 2) this.pagination.appendChild(this.createEllipsis());
        }

        for (let i = startPage; i <= endPage; i++) {
            this.pagination.appendChild(createPageItem(String(i), i, false, i === this.currentPage));
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) this.pagination.appendChild(this.createEllipsis());
            this.pagination.appendChild(createPageItem(String(totalPages), totalPages));
        }

        // "Next"
        this.pagination.appendChild(
            createPageItem("»", this.currentPage + 1, this.currentPage === totalPages, false, "Nächste Seite")
        );
    }

    createEllipsis() {
        const li = document.createElement("li");
        li.className = "page-item disabled";
        li.innerHTML = `<a class="page-link" tabindex="-1" aria-hidden="true">…</a>`;
        return li;
    }
}

export default new TableFilter('#attack-list', '#pagination', 30);
