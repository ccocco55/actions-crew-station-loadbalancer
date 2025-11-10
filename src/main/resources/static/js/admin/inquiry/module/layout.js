const inquireLayout = (function () {

    // 목록 비우기
    function clear() {
        const tbody = document.querySelector('#section-inquiry table tbody');
        if (tbody) tbody.innerHTML = '';

        const count = document.querySelector('#section-inquiry .count-amount');
        const pill1 = document.querySelectorAll('#section-inquiry .pill-row .span-amount')[0];
        const pill2 = document.querySelectorAll('#section-inquiry .pill-row .span-amount')[1];

        if (count) count.textContent = '0';
        if (pill1) pill1.textContent = '0';
        if (pill2) pill2.textContent = '0';
    }

    // 목록이 없을 때
    function showEmpty() {
        const tbody = document.querySelector('#section-inquiry table tbody');
        if (!tbody) return;
        tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center text-muted py-4">문의 내역이 없습니다.</td>
      </tr>
    `;

        const count = document.querySelector('#section-inquiry .count-amount');
        const pill1 = document.querySelectorAll('#section-inquiry .pill-row .span-amount')[0];
        const pill2 = document.querySelectorAll('#section-inquiry .pill-row .span-amount')[1];

        if (count) count.textContent = '0';
        if (pill1) pill1.textContent = '0';
        if (pill2) pill2.textContent = '0';
    }

    // 목록 출력
    function showList(list) {
        const tbody = document.querySelector('#section-inquiry table tbody');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!Array.isArray(list) || list.length === 0) {
            showEmpty();
            return;
        }

        let answered = 0;
        let unanswered = 0;

        list.forEach((item) => {
            if (item.inquiryStatus === 'ANSWERED') answered++;
            else unanswered++;

            const tr = document.createElement('tr');
            tr.dataset.id = item.id;

            tr.innerHTML = `
        <td>${item.id}</td>
        <td>${item.inquiryContent || ''}</td>
        <td>${item.createdDatetime || ''}</td>
        <td>${item.inquiryStatus === 'ANSWERED' ? '답변완료' : '미답변'}</td>
        <td>${item.replyDatetime || ''}</td>
        <td class="td-action text-center">
          <button type="button" class="action-btn view" data-id="${item.id}">
            <i class="mdi mdi-chevron-right"></i>
          </button>
        </td>
      `;
            tbody.appendChild(tr);
        });

        tbody.closest('#section-inquiry').style.display = 'block';

        const count = document.querySelector('#section-inquiry .count-amount');
        const pill1 = document.querySelectorAll('#section-inquiry .pill-row .span-amount')[0];
        const pill2 = document.querySelectorAll('#section-inquiry .pill-row .span-amount')[1];

        if (count) count.textContent = String(list.length);
        if (pill1) pill1.textContent = String(answered);
        if (pill2) pill2.textContent = String(unanswered);

        tbody.offsetHeight;
    }

    // 상세 보기
    function showDetail(data) {
        const modal = document.getElementById('inquiry-modal');
        if (!modal) return;

        modal.dataset.inquiryId = data.id || data.inquiryId || data.askId || '';
        console.log('[inquiry] modal.dataset.inquiryId =', modal.dataset.inquiryId);

        // 상단 상태
        const badge = modal.querySelector('.modal-title .badge-label');
        if (badge) {
            badge.textContent = data.inquiryStatus === 'ANSWERED' ? '답변완료' : '미답변';
            badge.className = data.inquiryStatus === 'ANSWERED'
                ? 'badge-label text-primary font-weight-bold ml-2'
                : 'badge-label text-danger font-weight-bold ml-2';
        }

        // 문의정보
        const infoTables = modal.querySelectorAll('.detail-info .info-table');
        if (infoTables[0]) {
            infoTables[0].querySelector('tbody').innerHTML = `
            <tr><th>문의번호</th><td>${data.id || data.inquiryId || ''}</td></tr>
            <tr><th>문의시간</th><td>${data.createdDatetime || ''}</td></tr>
        `;
        }
        if (infoTables[1]) {
            infoTables[1].querySelector('tbody').innerHTML = `
            <tr><th>문의 유형</th><td>-</td></tr>
            <tr><th>회원ID</th><td>${data.memberId || ''}</td></tr>
        `;
        }

        // 문의내용
        const contentTable = modal.querySelectorAll('.detail-info .info-table')[2];
        if (contentTable) {
            contentTable.querySelector('tbody').innerHTML = `
            <tr><th>문의내용</th><td>${data.inquiryContent || ''}</td></tr>
        `;
        }

        const replyInput = modal.querySelector('.inquiry-reply input, .inquiry-reply textarea');
        if (replyInput) replyInput.value = '';
    }


    // 모달 열기
    function openModal() {
        const modal = document.getElementById('inquiry-modal');
        if (!modal) return;
        modal.style.display = 'block';
        modal.classList.add('show');
        document.body.classList.add('modal-open');
    }

    // 모달 닫기
    function closeModal() {
        const modal = document.getElementById('inquiry-modal');
        if (!modal) return;
        modal.classList.remove('show');
        document.body.classList.remove('modal-open');
        modal.style.display = 'none';
    }

    return {
        clear,
        showEmpty,
        showList,
        showDetail,
        openModal,
        closeModal
    };
})();
