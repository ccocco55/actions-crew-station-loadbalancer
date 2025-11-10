// ===================== Member Service =====================
const memberProfileService = (() => {
    // 마이페이지 - 로그인된 멤버 프로필 조회
    const getMyPageProfile = async () => {
        try {
            const response = await fetch(`/api/mypage/profile`, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json"
                }
            });
            if (!response.ok) throw new Error(`Error: ${response.status}`);
            return await response.json(); // MemberProfileDTO 응답
        } catch (error) {
            console.error("getMyPageProfile Error:", error);
            return null;
        }
    };

    return {
        getMyPageProfile: getMyPageProfile
    };
})();



// ===================== Reply Service =====================
const replyService = (() => {
    // 내가 댓글 단 일기 목록 조회
    const getReplyDiaries = async (page = 1, size = 10) => {
        try {
            const response = await fetch(`/api/diaries/replies?page=${page}&size=${size}`);
            if (!response.ok) throw new Error(`Error: ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error("getReplyDiaries Error:", error);
            return { replyDiaryDTOs: [], criteria: { hasMore: false } };
        }
    };

    // 내가 댓글 단 일기 총 개수 조회
    const getReplyDiaryCount = async () => {
        try {
            const response = await fetch(`/api/diaries/replies/count`);
            if (!response.ok) throw new Error(`Error: ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error("getReplyDiaryCount Error:", error);
            return 0;
        }
    };

    return {
        getReplyDiaries: getReplyDiaries,
        getReplyDiaryCount: getReplyDiaryCount
    };
})();


// ===================== Like Service =====================
const likeService = (() => {
    // 좋아요한 일기 목록 조회 (로그인 정보에서 member 자동 인식)
    const getLikedDiaries = async (page = 1, size = 10) => {
        try {
            const response = await fetch(`/api/diaries/liked?page=${page}&size=${size}`);
            if (!response.ok) throw new Error(`Error: ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error("getLikedDiaries Error:", error);
            return { likedDiaryDTOs: [], criteria: { hasMore: false } };
        }
    };

    // 좋아요한 일기 총 개수 조회
    const getLikedDiaryCount = async () => {
        try {
            const response = await fetch(`/api/diaries/liked/count`);
            if (!response.ok) throw new Error(`Error: ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error("getLikedDiaryCount Error:", error);
            return 0;
        }
    };

    // 좋아요 취소 (별도 API — 컨트롤러에 DELETE /api/diaries/liked/{diaryId} 있음)
    const cancelLike = async (diaryId) => {
        try {
            const response = await fetch(`/api/diaries/liked/${diaryId}`, { method: "DELETE" });
            if (!response.ok) throw new Error(`Error: ${response.status}`);
            return await response.json(); // { success: true }
        } catch (error) {
            console.error("cancelLike Error:", error);
            return { success: false, message: error.message };
        }
    };

    return {
        getLikedDiaries: getLikedDiaries,
        getLikedDiaryCount: getLikedDiaryCount,
        cancelLike: cancelLike
    };
})();
