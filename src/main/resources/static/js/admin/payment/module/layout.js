const paymentLayout = (() => {

    const formatNumber = (value) => Number(value ?? 0).toLocaleString('ko-KR');
    const safeText = (value, defaultText = '-') =>
        value === null || value === undefined || value === '' ? defaultText : String(value);


    const getSection = () => document.querySelector('#section-payment');
    const getTableBody = () => getSection()?.querySelector('#payment-tbody');
    const getCountElement = () => getSection()?.querySelector('.receipt-count .count-amount');
    const getApprovedAmountElement = () => getSection()?.querySelector('.amount-box.revenue-box .span-amount');
    const getCanceledAmountElement = () => getSection()?.querySelector('.amount-box.cancel-box .span-amount');

    // 결제 상태
    const convertPhaseToKorean = (phase) => {
        const phaseUpper = String(phase ?? '').toUpperCase();
        if (phaseUpper.includes('PENDING') || phaseUpper.includes('PROGRESS')) return '결제대기중';
        if (phaseUpper.includes('SUCCESS')) return '결제완료';
        if (phaseUpper.includes('CANCEL') || phaseUpper.includes('REFUND')) return '결제취소';
        return '-';
    };

    const getPhaseColor = (phase) => {
        const phaseUpper = String(phase ?? '').toUpperCase();
        if (phaseUpper.includes('SUCCESS')) return '#40c8bc';
        if (phaseUpper.includes('CANCEL') || phaseUpper.includes('REFUND')) return '#fe657e';
        if (phaseUpper.includes('PENDING') || phaseUpper.includes('PROGRESS')) return '#8baaff';
        return '#888'; // 회색: 기타
    };

    const convertDeliveryMethod = (method) => {
        const normalized = String(method ?? '').toLowerCase();
        if (normalized === 'direct') return '직거래';
        if (normalized === 'parcel') return '택배거래';
        return '-';
    };


    const clear = () => {
        const tableBody = getTableBody();
        if (tableBody) tableBody.innerHTML = '';
        if (getCountElement()) getCountElement().textContent = '0';
        if (getApprovedAmountElement()) getApprovedAmountElement().textContent = '0';
        if (getCanceledAmountElement()) getCanceledAmountElement().textContent = '0';
    };

    const showEmptyTable = () => {
        const tableBody = getTableBody();
        if (!tableBody) return;
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center text-muted py-4">
                    조회된 결제가 없습니다.
                </td>
            </tr>`;
        if (getCountElement()) getCountElement().textContent = '0';
    };

     // 결제 목록 표시
    const showPayments = (response = {}) => {
        const tableBody = getTableBody();
        if (!tableBody) return;

        const paymentList = Array.isArray(response)
            ? response
            : response.content || response.payments || [];
        tableBody.innerHTML = '';

        if (!paymentList.length) {
            showEmptyTable();
            return;
        }

        const fragment = document.createDocumentFragment();

        paymentList.forEach((payment) => {
            const row = document.createElement('tr');
            row.dataset.paymentId = payment.id;

            const phaseText = convertPhaseToKorean(payment.paymentPhase);
            const phaseColor = getPhaseColor(payment.paymentPhase);
            const paidDate = safeText(payment.paidAt ?? payment.updatedDatetime);
            const deliveryMethod = convertDeliveryMethod(payment.deliveryType ?? payment.paymentMethod);


            row.innerHTML = `
                <td class="td-name"><div class="good-name">${safeText(payment.productName)}</div></td>
                <td class="td-amount text-right pr-4 font-weight-bold">
                    ${formatNumber(payment.amount)} <span class="amount-unit">원</span>
                </td>
                <td class="td-method"><div>${deliveryMethod}</div></td>
                <td class="td-method"><div>토스페이</div></td>
                <td class="td-status">
                    <span class="badge-label" style="color:${phaseColor}; font-weight:600;">
                        ${phaseText}
                    </span>
                </td>
                <td class="td-at text-center">
                    <div class="date-at text-dark">${paidDate}</div>
                </td>
                <td class="td-buyer text-center text-dark">
                    <div class="buyer-wrapper">
                        <div class="user-name">${safeText(payment.buyerName)}</div>
                    </div>
                </td>
                <td class="td-action text-center">
                    <button type="button" class="action-btn view" data-paymentid="${payment.id}">
                        <i class="mdi mdi-chevron-right"></i>
                    </button>
                </td>
            `;
            fragment.appendChild(row);
        });

        tableBody.appendChild(fragment);
        if (getCountElement()) getCountElement().textContent = String(paymentList.length);

        updateSummaryBox();
    };

     // 결제 요약 (승인/취소 합계)
    const updateSummaryBox = async (opt = {}) => {
        try {
        } catch (err) {
            console.error("결제 요약 불러오기 실패:", err);
        }
    };


    // 결제 상세 모달
    const showPaymentDetail = (detail = {}) => {
        const modal = document.getElementById('payment-modal');
        if (!modal) return;

        const bindText = (key, value) => {
            const element = modal.querySelector(`[data-bind="${key}"]`);
            if (element) element.textContent = safeText(value);
        };

        // 구매자 정보
        bindText('productName', detail.productName);
        bindText('amount', detail.amount != null ? `${formatNumber(detail.amount)}원` : '-');
        bindText('buyerName', detail.buyerName);
        bindText('buyerPhone', detail.buyerPhone);
        bindText('buyerEmail', detail.buyerEmail);
        bindText('address', detail.address);
        bindText('status', convertPhaseToKorean(detail.paymentPhase));
        bindText('paidAt', detail.paidAt ?? detail.createdDatetime ?? detail.updatedDatetime);

        // 판매자 정보
        bindText('sellerName', detail.sellerName);
        bindText('sellerPhone', detail.sellerPhone);
        bindText('sellerEmail', detail.sellerEmail);
        bindText('listedAt', detail.listedAt ?? '-');
        bindText('deliveryType', convertDeliveryMethod(detail.deliveryType));


        // 모달 열기
        modal.style.display = 'block';
        requestAnimationFrame(() => {
            modal.classList.add('show');
            modal.style.background = 'rgba(0,0,0,0.5)';
            document.body.classList.add('modal-open');
        });

        // 닫기 버튼 처리
        modal.querySelectorAll('.close, .btn-close').forEach((btn) => {
            btn.onclick = () => {
                modal.classList.remove('show');
                document.body.classList.remove('modal-open');
                setTimeout(() => (modal.style.display = 'none'), 150);
            };
        });
    };

    return {
        clear,
        showEmptyTable,
        showPayments,
        showPaymentDetail,
        updateSummaryBox,
    };
})();
