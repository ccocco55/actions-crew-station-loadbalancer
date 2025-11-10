const diariesListLayout = (() => {
    const showDiaries = async (result,check) => {
        let text = ``;

        const diaries = result.diaryDTOs;
        const tbody = document.querySelector("div.diary-card-feed");
        console.log(tbody)
        if(check){
            tbody.innerHTML= ""
        }
        if(result.criteria.total){
            console.log("실행")
            document.querySelector("div.search-page-empty").style.display = "none";
        }
        diaries.forEach((diary) => {
            let filePath= null
            if(diary.memberFilePath){
                filePath = diary.memberFilePath;
            } else if(diary.socialImgUrl){
                filePath = diary.socialImgUrl;
            }else{
                filePath = "https://image.ohousecdn.com/i/bucketplace-v2-development/uploads/default_images/avatar.png?w=144&h=144&c=c";
            }


                text += `
            <div class="card-feed-item-wrap">
                                    <article class="card-collection-item">
                                    <a class="card-writer-link" href="/member/profile/${diary.memberId}">
                                        <div class="card-writer">
                                            <div class="card-item-writer-content">
                                                <div class="card-item-writer-header">
                                                            
                                                            <img src="${filePath}" alt="" class="card-writer-img">
                                                            <div class="writer-info">
                                                                <span class="writer-name">${diary.memberName}</span>
                                                                
                                                            </div>
                                                           
                                                        
                                                        
                                                    </div>
                                            </div>
                                          </a>
                                        </div>
                                        <div class="card-collection-item-content">
                                            <div class="card-collection-item-img">
                                                <div class="card-item-img">
                                                    <img src="${diary.diaryFilePath}" alt="" class="image">
                                                    <div class="diary-img-count">+${diary.fileCount}</div>
                                                    <a class="card-content-link" href="/diaries/detail/${diary.postId}"></a>
                                                </div>
                                            </div>
                                            <a class="card-content-link" href="/diaries/detail/${diary.postId}"></a>
                                            <div class="card-item-description">
                                                <div class="card-item-description-content">
                                                    <span class="card-item-detail-content">
                                                       ${diary.postContent}
                                                    </span>
                                                </div>
                                            </div>
                                            <div class="card-item-action-list">
                                                <button class="card-item-action-btn like" data-post="${diary.postId}">
                                                    <svg class="icon icon--stroke ${diary.likeId ? 'active' : ''}" aria-label="좋아요" width="24" height="24" fill="currentColor" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" preserveAspectRatio="xMidYMid meet"><path d="M23.22 7.95c.4 4.94-2.92 9.71-10.92 13.85a.47.47 0 0 1-.42 0C3.88 17.66.56 12.9.96 7.93 1.54 2.48 8.28.3 12.1 4.7c3.8-4.4 10.55-2.22 11.13 3.25z"></path></svg>
                                                    <span class="count">${diary.diaryLikeCount}</span>
                                                </button>
                                                <button class="card-item-action-btn reply">
                                                    <svg class="icon icon-stroke" aria-label="댓글 달기" width="24" height="24" viewBox="0 0 24 24" preserveAspectRatio="xMidYMid meet"><path fill="currentColor" fill-rule="nonzero" d="M13.665 18.434l.53-.066C19.69 17.679 23 14.348 23 10c0-4.942-4.235-8.5-11-8.5S1 5.058 1 10c0 4.348 3.31 7.68 8.804 8.368l.531.066L12 21.764l1.665-3.33zm-3.985.926C3.493 18.585 0 14.69 0 10 0 4.753 4.373.5 12 .5S24 4.753 24 10c0 4.69-3.493 8.585-9.68 9.36l-1.647 3.293c-.374.75-.974.744-1.346 0L9.68 19.36z"></path></svg>
                                                    <span class="count">${diary.diaryReplyCount}</span>
                                                </button>
                                            </div>
                                        </div>
                                    </article>
                                </div>

            `
        })

        tbody.innerHTML += text;

    }
    return {showDiaries: showDiaries};
})();