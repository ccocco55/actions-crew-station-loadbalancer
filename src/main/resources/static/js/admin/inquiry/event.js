window.closeAllLayerUIs = function () {
    const popups = document.querySelectorAll('.bt-pop-menu.show, .bt-pop-menu-back.show, #pop-menu-bt2.show');
    popups.forEach(el => el.classList.remove('show'));

    const modals = document.querySelectorAll('.modal.show:not(#inquiry-modal), .payment-modal.show');
    modals.forEach(m => {
        m.classList.remove('show');
        m.style.display = 'none';
    });

    document.body.classList.remove('modal-open');
};

window.inquiryInit = async function () {
    console.log('[inquiryInit] 실행됨');

    window.inquireInited = true;

    await new Promise(r => requestAnimationFrame(() => setTimeout(r, 80)));

    window.closeAllLayerUIs();

    const section = document.getElementById('section-inquiry');
    if (section) {
        section.style.display = 'block';
        section.style.visibility = 'visible';
        section.style.opacity = '1';
    }

    await new Promise(resolve => {
        const check = () => {
            const tbody = section.querySelector('table tbody');
            if (tbody) return resolve();
            requestAnimationFrame(check);
        };
        check();
    });

    const modal = document.getElementById('inquiry-modal');
    const searchInput = section.querySelector('.filter-search input');
    const searchBtn = section.querySelector('.filter-search .btn-search');
    const filterBtn = section.querySelector('#button-filter-status');
    const filterPopup = section.querySelector('#pop-menu-bt2');
    const chkAns = section.querySelector('#checkboxactive1');
    const chkUnAns = section.querySelector('#checkboxactive2');
    const btnAll = section.querySelector('#allchecked1');
    const btnNone = section.querySelector('#allflasechecked1');
    const btnApply = filterPopup ? filterPopup.querySelector('.btn.btn-outline-primary.btn-sm') : null;
    const tbody = section.querySelector('table tbody');

    if (!tbody) {
        return;
    }

    // 상태 저장
    const state = { keyword: '', category: '' }; // '', 'ANSWERED', 'UNANSWERED'

    function calcCategory() {
        const a = chkAns && chkAns.classList.contains('is-checked');
        const u = chkUnAns && chkUnAns.classList.contains('is-checked');
        if (a && !u) state.category = 'ANSWERED';
        else if (!a && u) state.category = 'UNANSWERED';
        else state.category = '';
    }

    // 목록 불러오기
    async function loadList() {
        try {
            const list = await inquireService.getList({
                keyword: state.keyword,
                category: state.category
            });
            inquireLayout.showList(list);
        } catch (e) {
            console.error(e);
            if (inquireLayout.showEmpty) inquireLayout.showEmpty();
        }
    }

    // 최초 로드
    await loadList();

    // 검색 버튼
    if (searchBtn && !searchBtn.bound) {
        searchBtn.bound = true;
        searchBtn.addEventListener('click', async function (e) {
            e.preventDefault();
            state.keyword = (searchInput && searchInput.value.trim()) || '';
            await loadList();
        });
    }

    // 검색 엔터키
    if (searchInput && !searchInput.bound) {
        searchInput.bound = true;
        searchInput.addEventListener('keydown', async function (e) {
            if (e.key === 'Enter') {
                state.keyword = searchInput.value.trim();
                await loadList();
            }
        });
    }

    // 필터 버튼
    if (filterBtn && !filterBtn.bound) {
        filterBtn.bound = true;
        filterBtn.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            if (filterPopup) filterPopup.classList.toggle('show');
        });
    }

    if (filterPopup && !filterPopup.bound) {
        filterPopup.bound = true;
        filterPopup.addEventListener('click', function (e) {
            e.stopPropagation();
        });
    }

    document.addEventListener('click', function (e) {
        if (e.target.closest('.modal.show')) return;
        const visible = section && section.offsetParent !== null;
        if (!visible) return;
        if (filterPopup) filterPopup.classList.remove('show');
    });

    // 필터 옵션 버튼
    btnAll?.addEventListener('click', function (e) {
        e.preventDefault();
        chkAns?.classList.add('is-checked');
        chkUnAns?.classList.add('is-checked');
    });

    btnNone?.addEventListener('click', function (e) {
        e.preventDefault();
        chkAns?.classList.remove('is-checked');
        chkUnAns?.classList.remove('is-checked');
    });

    chkAns?.addEventListener('click', function () {
        chkAns.classList.toggle('is-checked');
    });

    chkUnAns?.addEventListener('click', function () {
        chkUnAns.classList.toggle('is-checked');
    });

    btnApply?.addEventListener('click', async function (e) {
        e.preventDefault();
        calcCategory();
        filterPopup?.classList.remove('show');
        await loadList();
    });

    // 상세 보기
    if (tbody && !tbody.bound) {
        tbody.bound = true;
        tbody.addEventListener('click', async function (e) {
            const btn = e.target.closest('.action-btn.view, .td-action .action-btn');
            if (!btn) return;

            const id = btn.dataset.id || btn.closest('tr')?.dataset.id;
            if (!id) return;

            try {
                const dto = await inquireService.getDetail(id);
                inquireLayout.showDetail(dto);

                // 모달 열기
                if (typeof inquireLayout.openModal === 'function') {
                    inquireLayout.openModal();
                } else if (modal) {
                    modal.classList.add('show');
                    modal.style.display = 'block';
                    document.body.classList.add('modal-open');
                    modal.style.background = 'rgba(0,0,0,0.5)';
                    modal.style.pointerEvents = 'auto';
                }
            } catch (err) {
                console.error('문의 상세 조회 실패', err);
                alert('상세 조회에 실패했습니다.');
            }
        });
    }

    // 모달 동작
    if (modal && !modal.bound) {
        modal.bound = true;
        modal.addEventListener('click', async function (e) {
            const target = e.target;

            if (target.closest('[data-role="inquiry-close"], .btn-close, .close')) {
                e.preventDefault();
                inquireLayout.closeModal?.() ??
                    modal.classList.remove('show');
                    modal.style.display = 'none';
                    document.body.classList.remove('modal-open');
                return;
            }

            // 답변하기
            const replyBtn = target.closest('button, a');
            if (replyBtn) {
                const text = replyBtn.textContent.trim();
                const isReply = text === '답변하기' || replyBtn.classList.contains('btn-reply');
                if (isReply) {
                    e.preventDefault();
                    const id = modal.dataset.inquiryId;
                    const input = modal.querySelector('.inquiry-reply input, .inquiry-reply textarea');
                    const content = input?.value.trim() || '';

                    if (!id) return alert('유효하지 않은 문의입니다.');
                    if (!content) return alert('답변 내용을 입력해 주세요.');

                    try {
                        await inquireService.postReply(id, content);
                        inquireLayout.closeModal?.();
                        await loadList();
                    } catch (err) {
                        console.error('답변 등록 실패', err);
                        alert('답변 등록에 실패했습니다.');
                    }
                }
            }
        });

        // 배경 클릭 & ESC
        modal.addEventListener('mousedown', e => {
            if (e.target === modal) inquireLayout.closeModal?.();
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && modal.classList.contains('show'))
                inquireLayout.closeModal?.();
        });
    }
};


