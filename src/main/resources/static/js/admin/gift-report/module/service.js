const giftReportService = (() => {
    const getReports = async (page = 1) => {
        const res = await fetch(`/api/admin/gifts?page=${page}`,
            { credentials: 'include' });
        if (!res.ok) {
            console.error('신고 목록 로드 실패');
            return [];
        }
        return await res.json();
    };

    const processReport = async (reportId, postId = null, hidePost = false) => {
        const params = new URLSearchParams();
        if (postId) params.append("postId", postId);
        if (hidePost) params.append("hidePost", hidePost);

        const res = await fetch(`/api/admin/gift/${reportId}/process?${params.toString()}`, {
            method: "POST",
            credentials: 'include',
        });

        if (!res.ok) {
            console.error("신고 처리 실패");
            return false;
        }

        return true;
    };

    return { getReports, processReport };
})();
