const DiaryLayout = (() => {

    // 상단 개수 표시 업데이트
    const updateDiaryCount = (count) => {
        const tagName = document.querySelector(".tag-name");
        if (tagName) tagName.textContent = `전체(${count})`;
    };

    // 다이어리 목록 렌더링
    const renderDiaryList = (diaries, append = false) => {
        const container = document.querySelector(".diary-container-inner");
        if (!append) container.innerHTML = ""; 

        if (!diaries || diaries.length === 0) {
            if (!append) container.innerHTML = `<p class="user-project-feed__empty">결과가 존재하지 않습니다.</p>`;
            return;
        }

        diaries.forEach(diary => {
            const diaryHTML = `
                <div class="diary-wrap">
                    <div class="diary-div">
                        <a href="/diaries/detail/${diary.postId}">
                            <div class="diary-img-wrap">
                                <img class="diary-img" src="${diary.mainImage || '/images/default-diary.jpg'}">
                                <div class="date-tag">
                                    <span class="tag-span">${diary.formattedCreatedDatetime}</span>
                                </div>
                                <p class="diary-title">${diary.postTitle || '제목 없음'}</p>
                                <p class="diary-content">${diary.postContent || ''}</p>
                            </div>
                        </a>
                    </div>
                </div>
            `;
            container.insertAdjacentHTML("beforeend", diaryHTML);
        });
    };

    return {
        renderDiaryList : renderDiaryList,
        updateDiaryCount: updateDiaryCount
    };
})();
