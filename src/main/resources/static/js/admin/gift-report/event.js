window.giftReportInit = async function () {
    if (window.giftReportInited) return;
    window.giftReportInited = true;

    const section = document.getElementById('section-gift-report');
    if (!section) return;

    // 무한 스크롤 상태
    let page = 1, canScroll = true, hasMore = true;

    const load = async (p = 1) => {
        const reports = await giftReportService.getReports(p);
        giftReportLayout.showReportGiftList(reports);
        hasMore = Array.isArray(reports) && reports.length > 0;
    };

    await load(page);

    const container = document.querySelector('#bootpay-main');
    if (container && !container.__giftScrollBound) {
        container.__giftScrollBound = true;
        container.addEventListener('scroll', async () => {
            const { scrollTop, clientHeight, scrollHeight } = container;
            if (scrollTop + clientHeight >= scrollHeight - 100) {
                if (canScroll && hasMore) {
                    canScroll = false;
                    await load(++page);
                    setTimeout(() => { if (hasMore) canScroll = true; }, 800);
                }
            }
        });
    }

    // ===== 모달 =====
    const modal = section.querySelector('.report-modal');
    if (!modal) return;

    const bind = (key, val) => {
        const el = modal.querySelector(`[data-bind="${key}"]`);
        if (el) el.textContent = val ?? '';
    };

    let currentRow = null;

    const open = (row) => {
        currentRow = row;
        const title = row.querySelector('.post-title').textContent.trim() ?? '-';
        const author = row.querySelector('.post-meta b').textContent.trim() ?? '-';
        const postIdText = row.querySelector('.post-meta .meta:last-child').textContent.trim() ?? 'postId: -';
        const postId = postIdText.replace(/^postId:\s*/i, '') || '-';
        const reason = row.querySelector('.reason-badge').textContent.trim() ?? '-';
        const reporterName = row.querySelector('td:nth-child(3) b').textContent.trim() ?? '-';
        const reporterEmail = row.querySelector('td:nth-child(3) .text-muted').textContent.trim() ?? '-';
        const reportedAt = row.querySelector('td:nth-child(4)').textContent.trim() ?? '-';
        const badgeInRow = row.querySelector('.approval-status');

        bind('title', title);
        bind('author', author);
        bind('postId', postId);
        bind('reason', reason);
        bind('reporterName', reporterName);
        bind('reporterEmail', reporterEmail);
        bind('reportedAt', reportedAt);

        const badgeInModal = modal.querySelector('[data-bind="statusBadge"]');
        if (badgeInModal) {
            badgeInModal.className = 'status-badge';
            if (badgeInRow.classList.contains('status-resolved')) {
                badgeInModal.classList.add('status-resolved'); badgeInModal.textContent = '처리완료';
            } else {
                badgeInModal.classList.add('status-pending');  badgeInModal.textContent = '대기중';
            }
        }

        modal.style.display = 'block';
        requestAnimationFrame(() => {
            modal.classList.add('show');
            modal.style.background = 'rgba(0,0,0,.5)';
            document.body.classList.add('modal-open');
        });
    };

    const close = () => {
        modal.classList.remove('show');
        document.body.classList.remove('modal-open');
        setTimeout(() => modal.style.display = 'none', 120);
    };

    // 섹션 내부에서만 클릭 위임
    section.addEventListener('click', (e) => {
        const viewBtn = e.target.closest('.action-btn.view');
        if (viewBtn) {
            const row = viewBtn.closest('tr'); if (row) open(row);
        }
        if (e.target.closest('.btn-close, .close')) close();
    });

    const approveBtn = modal.querySelector('.btn-approve');
    approveBtn?.addEventListener('click', async () => {
        if (!currentRow) return;
        const reportId = currentRow.dataset.reportId;
        const postIdText = currentRow.querySelector('.post-meta .meta:last-child').textContent.trim() ?? '';
        const postId = postIdText.replace(/^postId:\s*/i, '');
        const hidePost = modal.querySelector('.cb-hide-post').checked || false;

        const ok = await giftReportService.processReport(reportId, postId, hidePost);
        if (!ok) { alert('신고 처리에 실패했습니다.'); return; }

        const badge = currentRow.querySelector('.approval-status');
        if (badge) {
            badge.textContent = '처리완료';
            badge.classList.remove('status-pending'); badge.classList.add('status-resolved');
        }
        const badgeInModal = modal.querySelector('[data-bind="statusBadge"]');
        if (badgeInModal) { badgeInModal.className = 'status-badge status-resolved'; badgeInModal.textContent = '처리완료'; }
        close();
    });
};
