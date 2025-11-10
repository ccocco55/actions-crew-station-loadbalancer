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

const DiaryService = (() => {

    // 나의 다이어리 목록 조회 (무한스크롤)
    const getMyDiaryList = async (page = 1, size = 10) => {
        try {
            const response = await fetch(`/api/mypage/diary/list?page=${page}&size=${size}`);
            if (!response.ok) throw new Error("다이어리 목록 조회 실패");
            return await response.json();
        } catch (error) {
            console.error("getMyDiaryList error:", error);
            return null;
        }
    };

    // 나의 다이어리 총 개수 조회
    const getMyDiaryCount = async () => {
        try {
            const response = await fetch(`/api/mypage/diary/count`);
            if (!response.ok) throw new Error("다이어리 총 개수 조회 실패");
            return await response.json(); // int 값 반환
        } catch (error) {
            console.error(" getMyDiaryCount error:", error);
            return 0;
        }
    };

    return { getMyDiaryList : getMyDiaryList,
            getMyDiaryCount : getMyDiaryCount};
})();