const crewReportService = (() => {
        const getCrewReport = async (page = 0, type = 'LONG') => {
            try {
                const res = await fetch(`/api/admin/accompanies?page=${page}&accompanyStatus=${type}`, {
                    credentials: 'include',
                });

                if (!res.ok) {
                    console.error('신고 목록 불러오기 실패');
                    return [];
                }

                const data = await res.json();
                return Array.isArray(data) ? data : [];
            } catch (err) {
                console.error('연결 오류:', err);
                return [];
            }
        };

    const processReport = async (reportId, postId, hidePost = false) => {
        try {
            const url = `/api/admin/accompanies/${reportId}/process?postId=${postId ?? ''}&hidePost=${hidePost}`;
            const res = await fetch(url, {
                method: 'POST',
                credentials: 'include',
            });

            if (!res.ok) {
                console.error('신고 처리 실패');
                return false;
            }

            return true;
        } catch (err) {
            console.error('네트워크 오류:', err);
            return false;
        }
    };


    return { getCrewReport: getCrewReport, processReport:processReport };

})();