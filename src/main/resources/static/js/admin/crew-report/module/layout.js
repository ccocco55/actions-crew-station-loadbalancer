const section = document.getElementById('section-crew-report');
const crewReportLayout = (() => {
    // 목록 렌더링
    function list(items = []) {
        const tbody = section.querySelector("#registerCrewReportList");
        if (!tbody) return;

        if (!items.length) {
            tbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center text-muted" style="padding:32px 0;">
            신고 내역이 없습니다.
          </td>
        </tr>`;
            return;
        }

        tbody.innerHTML = items.map((d) => {
            const writer = d.writerEmail ?? d.writerSocialEmail ?? "익명";
            const reporter = d.reporterEmail ?? d.reporterSocialEmail ?? "익명";
            const createdAt = (d.createdDatetime || "").slice(0, 16);
            const reason = d.reportContent ?? "-";
            const status = String(d.processStatus || "").toLowerCase();
            const statusText  = status === "resolved" ? "처리완료" : "대기중";
            const statusClass = status === "resolved" ? "status-done"  : "status-pending";

            return `
        <tr data-id="${d.reportId}" data-type="${(d.accompanyStatus || 'long').toLowerCase()}" data-status="${status}">
          <td class="td-post">
            <div class="post-title">${d.postTitle || ""}</div>
            <div class="post-meta">
              <span class="meta">by <b>${writer}</b></span>
              <span class="dot">·</span>
              <span class="meta">postId: ${d.postId}</span>
            </div>
          </td>
          <td class="text-center">
            <span class="badge badge-label reason-badge text-danger">${d.reportContent}</span>
          </td>
          <td>
            <div>reporter: <b>${reporter.split("@")[0]}</b></div>
            <div class="text-muted">${reporter}</div>
          </td>
          <td class="text-center text-muted">${createdAt}</td>
          <td class="td-actions text-right">
            <span class="approval-status status-badge ${statusClass}">${statusText}</span>
            <button class="btn btn-light-danger btn-sm action-btn view" data-id="${d.reportId}" title="상세보기">
              <i class="mdi mdi-chevron-right"></i>
            </button>
          </td>
        </tr>`;
        }).join("");
    }

    // 모달 열기
    function openModal(row, reportId) {
        const modal = section.querySelector('.report-modal');
        if (!modal) {
            console.warn('모달 엘리먼트를 찾지 못했습니다.');
            return;
        }

        const title = row.querySelector(".post-title")?.textContent?.trim() || "";
        const writer = row.querySelector(".post-meta b")?.textContent || "-";
        const postId = Number((row.querySelector(".post-meta .meta:last-child")?.textContent.match(/\d+/) || [0])[0]);
        const reason = row.querySelector(".reason-badge")?.textContent || "-";
        const reportedAt = row.querySelector("td.text-center.text-muted")?.textContent || "-";
        const statusText = row.querySelector(".approval-status")?.textContent || "대기중";

        modal.querySelector('[data-bind="title"]').textContent = title;
        modal.querySelector('[data-bind="author"]').textContent = writer;
        modal.querySelector('[data-bind="postId"]').textContent = String(postId);
        modal.querySelector('[data-bind="reason"]').textContent = reason;
        modal.querySelector('[data-bind="reportedAt"]').textContent = reportedAt;
        modal.querySelector('[data-bind="statusBadge"]').textContent = statusText;

        const cbHide = modal.querySelector(".cb-hide-post");
        const btnApprove = modal.querySelector(".btn-approve");
        const btnClose = modal.querySelector(".btn-close");
        const btnX = modal.querySelector(".modal-header .close");

        if (cbHide) cbHide.checked = false;

        btnApprove.onclick = async (e) => {
            const ok = await crewReportService.processReport(reportId, postId, !!cbHide?.checked);
            if (ok) {
                closeModal();
                const t = getInitType().toUpperCase();
                const items = await crewReportService.getCrewReport(0, t);
                crewReportLayout.list(items);
            } else {
                alert("처리에 실패했습니다.");
            }
        };

        btnClose.onclick = closeModal;
        btnX.onclick = closeModal;

        modal.style.display = "block";
        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");
    }

    // 모달 닫기
    function closeModal() {
        const modal = section.querySelector(".report-modal");
        if (!modal) return;
        modal.classList.remove("show");
        modal.style.display = "none";
        modal.setAttribute("aria-hidden", "true");
    }

    return { list, openModal, closeModal };
})();
