// 스크롤 탑 버튼 (클릭시 목록 최상단)
const scrollTopBtn = document.getElementById("scrollTopBtn");

scrollTopBtn.addEventListener("click", () => {
    window.scrollTo({top: 0, behavior: "smooth"});
});

window.addEventListener("scroll", () => {
    if (window.scrollY > 200) {
        scrollTopBtn.classList.add("show");
    } else {
        scrollTopBtn.classList.remove("show");
    }
});


// 마감 시각 표시
function startCountdown() {

    const timers = document.querySelectorAll("div.product-limit-time-wrapper");
    // console.log(first,last);
    // let timerArray = Array.from(timers);
    // timerArray = timerArray.slice(first, last)

    timers.forEach(timer => {
        const endTime = new Date(timer.dataset.endtime);


        function updateTimer() {
            const now = new Date();
            const diff = endTime - now;
            console.log(diff);
            if (diff <= 0) {
                timer.textContent = "마감";
                return;
            }

            const totalSeconds = Math.floor(diff / 1000);

            const days = Math.floor(totalSeconds / (3600 * 24));
            const hours = String(Math.floor((totalSeconds % (3600 * 24)) / 3600)).padStart(2, "0");
            const minutes = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, "0");
            const seconds = String(totalSeconds % 60).padStart(2, "0");

            if (days > 0) {
                timer.textContent = `${days}일 ${hours}:${minutes}:${seconds} 남음`;
            } else {
                timer.textContent = `${hours}:${minutes}:${seconds} 남음`;
            }
        }

        updateTimer();
        timer.dataset.timeout = String(setInterval(updateTimer, 1000));
    });
}

let page = 1;
const urlParams = new URLSearchParams(window.location.search);
let keyword = urlParams.get('keyword') || "";
let timerIndex = 0;
let checkMore = true;
let checkScroll = true;
const showList = async (page = 1, keyword = "", index = 0) => {
    console.log("시작")
    purchases = await purchaseListService.getPurchases(purchaseListLayout.showPurchases, page, keyword);
    keyword = purchases.search.keyword;
    checkMore = purchases.criteria.hasMore;
    console.log(purchases)
    console.log(keyword)
    console.log("종료")
    let lastIndex = purchases.purchaseDTOs.length;
    console.log("시작해보자")
    setTimeout(() => {
        startCountdown()
    }, 500);

    console.log("종료해보자")
    timerIndex += index + lastIndex;
    console.log(timerIndex)
}
showList(page, keyword, timerIndex);


window.addEventListener("scroll", async (e) => {

    if (!checkMore) {
        return;
    }
    if (!checkScroll) {
        return;
    }
    // 현재 스크롤 위치
    const scrollTop = window.scrollY

    // 화면 높이
    const windowHeight = window.innerHeight;

    // 문서 전체 높이
    const documentHeight = document.documentElement.scrollHeight
    if (scrollTop + windowHeight >= documentHeight - 500) {
        //     바닥에 닿았을 때
        if (checkScroll) {
            checkScroll = false;
            console.log("몇 번 실행되니")
            const timers = document.querySelectorAll("div.product-limit-time-wrapper");
            timers.forEach(timer=>{
                clearInterval(Number(timer.dataset.timeout));
            })
            document.getElementById("loading").style.display = "block";
            purchases = await purchaseListService.getPurchases(purchaseListLayout.showPurchases, ++page, keyword);
            keyword = purchases.search.keyword;
            checkMore = purchases.criteria.hasMore;
            let lastIndex = purchases.purchaseDTOs.length;
            console.log("시작해보자")
            setTimeout(() => {
                startCountdown();
                timerIndex += lastIndex
                if(checkMore){
                    checkScroll = true;
                }
                document.getElementById("loading").style.display = "none";
                console.log("지금 실행")
            }, 500);
        }

    }
})