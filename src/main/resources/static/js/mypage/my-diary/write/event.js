const countries = [
    "가나",
    "가봉",
    "가이아나",
    "감비아",
    "과테말라",
    "그레나다",
    "그리스",
    "기니",
    "기니비사우",
    "나미비아",
    "나우루",
    "나이지리아",
    "남수단",
    "남아프리카공화국",
    "네덜란드",
    "네팔",
    "노르웨이",
    "뉴질랜드",
    "니카라과",
    "니제르",
    "대한민국",
    "덴마크",
    "도미니카공화국",
    "도미니카연방",
    "독일",
    "동티모르",
    "라오스",
    "라이베리아",
    "라트비아",
    "러시아",
    "레바논",
    "레소토",
    "루마니아",
    "룩셈부르크",
    "르완다",
    "리비아",
    "리투아니아",
    "리히텐슈타인",
    "마다가스카르",
    "마셜제도",
    "말라위",
    "말레이시아",
    "말리",
    "멕시코",
    "모나코",
    "모로코",
    "모리셔스",
    "모리타니",
    "모잠비크",
    "몬테네그로",
    "몰도바",
    "몰디브",
    "몰타",
    "몽골",
    "미국",
    "미얀마",
    "미크로네시아",
    "바누아투",
    "바레인",
    "바베이도스",
    "바하마",
    "방글라데시",
    "베냉",
    "베네수엘라",
    "베트남",
    "벨기에",
    "벨라루스",
    "벨리즈",
    "보스니아헤르체고비나",
    "보츠와나",
    "볼리비아",
    "부룬디",
    "부르키나파소",
    "부탄",
    "북마케도니아",
    "북한",
    "불가리아",
    "브라질",
    "브루나이",
    "사모아",
    "사우디아라비아",
    "사이프러스",
    "산마리노",
    "상투메프린시페",
    "세네갈",
    "세르비아",
    "세이셸",
    "세인트루시아",
    "세인트빈센트그레나딘",
    "세인트키츠네비스",
    "소말리아",
    "솔로몬제도",
    "수단",
    "수리남",
    "스리랑카",
    "스웨덴",
    "스위스",
    "스페인",
    "슬로바키아",
    "슬로베니아",
    "시리아",
    "시에라리온",
    "싱가포르",
    "아랍에미리트",
    "아르메니아",
    "아르헨티나",
    "아이슬란드",
    "아이티",
    "아일랜드",
    "아제르바이잔",
    "아프가니스탄",
    "안도라",
    "알바니아",
    "알제리",
    "앙골라",
    "앤티가바부다",
    "에콰도르",
    "에스와티니",
    "에스토니아",
    "에티오피아",
    "엘살바도르",
    "영국",
    "예멘",
    "오만",
    "오스트리아",
    "온두라스",
    "요르단",
    "우간다",
    "우루과이",
    "우즈베키스탄",
    "우크라이나",
    "이라크",
    "이란",
    "이스라엘",
    "이집트",
    "이탈리아",
    "인도",
    "인도네시아",
    "일본",
    "잠비아",
    "적도기니",
    "조지아",
    "중앙아프리카공화국",
    "중국",
    "지부티",
    "짐바브웨",
    "체코",
    "칠레",
    "카메룬",
    "카보베르데",
    "카자흐스탄",
    "카타르",
    "캄보디아",
    "캐나다",
    "케냐",
    "코모로",
    "코스타리카",
    "코트디부아르",
    "콜롬비아",
    "콩고공화국",
    "콩고민주공화국",
    "쿠바",
    "쿠웨이트",
    "쿡제도",
    "크로아티아",
    "키르기스스탄",
    "키리바시",
    "타지키스탄",
    "탄자니아",
    "태국",
    "토고",
    "통가",
    "투르크메니스탄",
    "투발루",
    "튀니지",
    "튀르키예",
    "트리니다드토바고",
    "파나마",
    "파라과이",
    "파키스탄",
    "파푸아뉴기니",
    "팔라우",
    "팔레스타인",
    "페루",
    "포르투갈",
    "폴란드",
    "프랑스",
    "피지",
    "핀란드",
    "필리핀",
];

const countryInput = document.querySelector(".input-tag-wrap");
const countryDropdown = document.getElementById("countryDropdown");
let checkDrop = false;
if (countryInput && countryDropdown) {
    countryInput.addEventListener("input", () => {
        console.log("들어옴");
        const value = countryInput.value.trim();
        countryDropdown.innerHTML = "";

        if (!value) {
            countryDropdown.style.display = "none";
            return;
        }

        const filtered = countries.filter((c) => c.includes(value));

        if (filtered.length) {
            filtered.forEach((country) => {
                const li = document.createElement("li");
                li.textContent = country;
                li.addEventListener("click", () => {
                    countryInput.value = country;
                    countryDropdown.style.display = "none";
                    checkDrop = true;
                });
                countryDropdown.appendChild(li);
            });
            countryDropdown.style.display = "block";
        } else {
            countryDropdown.style.display = "none";
        }
    });

    // 바깥 클릭 시 닫기
    document.addEventListener("click", (e) => {
        if (!e.target.closest(".autocomplete")) {
            countryDropdown.style.display = "none";
        }
    });
}

const tagPin = `
                          <button class="tag-add-btn" type="button">
                            <svg width="18" height="18" viewBox="0 0 24 24" class="plus-img">
                              <circle cx="12" cy="12" r="12" fill="#647FBC"></circle>
                              <path stroke="#FFF" stroke-width="2" d="M12 16V8m-4 4h8"></path>
                            </svg>
                          </button>
                          <div class="mention-window">
                                <div class="triangle"></div>
                                <div class="mention-profile">
                                    <a class="profile-a">
                                        <div class="mention-profile-img">
                                            <img src="https://prs.ohousecdn.com/apne2/any/uploads/productions/v1-356976242864128.jpg?c=c&amp;w=320&amp;h=320">
                                        </div>
                                        <span id="mention-name">크루원 이름</span>
                                    </a>
                                </div>
                            </div>
                        `;

const pickFile = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/*";
    input.hidden = true;
    document.body.appendChild(input);
    return input;
};
const show = (el) => el && (el.hidden = false);
const hide = (el) => el && (el.hidden = true);

const leftList = document.querySelector(".left-img-add-container");
const contentList = document.querySelector(".post-img-content-container");
const thumbTpl = document.querySelector("#thumb-tpl");
let sampleBlock = document.querySelector(".post-img-content-wrapper");
const tagModal = document.querySelector(".modal-popout");
const closeModalBtn = document.querySelector(".close-btn");
let currentBlock = null;
console.log(sampleBlock);

// 편집 버튼 초기 라벨 통일
const editButtons = document.querySelectorAll(".edit-button");
editButtons.forEach((btn) => {
    btn.textContent = "+ 태그 추가";
});

// 왼쪽 + 는 하나만 남기기
if (leftList) {
    const plusItems = leftList.querySelectorAll(".post-sub-img.add");
    for (let i = 1; i < plusItems.length; i++) plusItems[i].remove();
}

//  블록 초기화/미리보기/인덱스
const delImageNone = (msg) => {
    console.log("입장했어");
    console.log(msg);

    if (
        document.querySelectorAll(".post-img-content-wrapper .content-del")
            .length <= 2
    ) {
        console.log("delImageNone 확인");

        document
            .querySelectorAll(".post-img-content-wrapper .content-del")
            .forEach((data) => {
                data.style.display = "none";
            });
    }
};
const resetBlock = (block) => {
    block.dataset.idx = "";
    block.querySelector(".img-add-container img")?.remove();
    // block.querySelector(".content-del").style.display = "none";
    const split = block.id.split("_");
    block.id = split[0] + "_" + +split[1];
    show(block.querySelector(".dropzone"));
    hide(block.querySelector(".post-img-bottom"));
    hide(block.querySelector(".img-tag-container"));
    block.querySelectorAll(".img-tag-container").forEach((data) => {
        data.remove();
    });
    const btn = block.querySelector(".edit-button");
    if (btn) btn.textContent = "+ 태그 추가";

    const ta = block.querySelector(".post-input");
    if (ta) ta.value = "";
    block.dataset.idx = "0";
    console.log(123131321313);

    block.dataset.armed = "0";
};

const previewIn = (block, url) => {
    const box = block.querySelector(".img-add-container");
    console.log(box.previousElementSibling);
    box.previousElementSibling.style.display = "none";

    let img = box.querySelector("img");
    if (!img) {
        img = document.createElement("img");
        img.className = "css-n9shyu";
        box.appendChild(img);
    }
    img.src = url;
    hide(block.querySelector(".dropzone"));
    show(block.querySelector(".post-img-bottom"));
};

// 인덱스: 빈 슬롯 먼저 사용
let nextIdx = 1;
const freeIdx = [];
const takeIdx = () => (freeIdx.length ? freeIdx.shift() : nextIdx++);
const giveIdx = (i) => {
    const pos = freeIdx.findIndex((v) => v > i);
    if (pos === -1) freeIdx.push(i);
    else freeIdx.splice(pos, 0, i);
};

// 삽입 위치(오름차순 유지)
const findThumbBefore = (idx) => {
    const list = leftList.querySelectorAll(".post-sub-img:not(.add)");
    for (const li of list) if (+li.dataset.idx > idx) return li;
    return leftList.querySelector(".post-sub-img.add");
};
const findBlockBefore = (idx) => {
    const list = contentList.querySelectorAll(
        ".post-img-content-wrapper[data-idx]"
    );
    for (const li of list) if (+li.dataset.idx > idx) return li;
    return null;
};

// 파일로 한 쌍 만들기 (왼쪽 썸네일 + 오른쪽 블록)
const addPairWithFile = () => {
    console.log(sampleBlock.querySelector(".content-del"));
    fileBuffer.push("")
    const idx = document.querySelectorAll(".post-img-content-wrapper").length;
    console.log(idx + "확인부탁");
    console.log(freeIdx);

    // 블록: 첫 템플릿이 비어있고 idx==0이면 재사용, 아니면 복제
    let block;

    // if (firstIsEmpty && idx === 0) {
    //     block = sampleBlock;
    // } else {
    // if (idx === 0) return;
    sampleBlock = document.querySelector(
        `.post-img-content-wrapper[data-idx="0"]`
    );
    if (!sampleBlock.querySelector(".img-add-container img")) {
        sampleBlock.querySelector(".content-del").style.display = "block";
    } else {
        sampleBlock.querySelector(".content-del").style.display = "none";
    }
    block = sampleBlock.cloneNode(true);
    block.querySelector(".content-del").style.display = "block";
    resetBlock(block);
    fileBuffer.push("");
    // }
    block.dataset.idx = String(idx);
    const beforeBlk = findBlockBefore(idx);
    beforeBlk
        ? contentList.insertBefore(block, beforeBlk)
        : contentList.appendChild(block);
    // 왼쪽 썸네일
    const thumb = document.importNode(thumbTpl.content, true).firstElementChild;
    thumb.dataset.idx = String(idx);
    thumb.style.display = "none"; // list-item
    const imgView = thumb.querySelector(".img-view");
    if (imgView)
        imgView.src =
            "https://image.ohousecdn.com/i/bucketplace-v2-development/uploads/cards/project/172422271039389131.JPG?w=1700&h=1020&c=c";
    const beforeThumb = findThumbBefore(idx);
    // 왼쪽 썸네일 추가
    leftList.insertBefore(thumb, beforeThumb);
    console.log(sampleBlock);
};

// 왼쪽 영역 (추가/삭제/스크롤)
// + 버튼 → 파일 선택 → 쌍 추가
leftList?.addEventListener("click", (e) => {
    if (!e.target.closest(".sub-img-plus-btn-container")) return;
    addPairWithFile();
    // const input = pickFile();
    // input.onchange = () => {
    //     const f = input.files?.[0];
    //     if (f)
    //     input.remove();
    // };
    // input.click();
});

// 썸네일 삭제
leftList?.addEventListener("click", (e) => {
    const del = e.target.closest(".delete-sub-img");
    if (!del) return;
    const li = del.closest(".post-sub-img:not(.add)");
    const idx = +li.dataset.idx;
    console.log(idx + "뭐냐 이거는 ");
    //  0이고 길이도 0이야
    if (
        !idx &&
        document.querySelectorAll(".post-sub-img:not(.add)").length === 1
    ) {
        console.log(123);
        li.style.display = "none";
        // contentList
        //     .querySelector(`.post-img-content-wrapper[data-idx="${idx}"] img`)
        //     .remove();
        contentList
            .querySelector(`.post-img-content-wrapper[data-idx="${idx}"] img`)
            .remove();

        contentList.appendChild(sampleBlock);
        resetBlock(sampleBlock);
        sampleBlock.querySelector(".content-del").style.display = "none";
    } else {
        // 0이거나 길이가 1이상이거나
        li.remove();
        delImageNone("왼쪽에서 삭제");
        contentList
            .querySelector(`.post-img-content-wrapper[data-idx="${idx}"]`)
            ?.remove();
    }
    document
        .querySelectorAll(".post-img-content-wrapper")
        .forEach((data, idx) => {
            data.dataset.idx = idx;
        });
    document
        .querySelectorAll(".post-sub-img:not(.add)")
        .forEach((data, index) => {
            console.log(data);
            data.dataset.idx = index;
        });
    // contentList
    //     .querySelector(`.post-img-content-wrapper[data-idx="${idx}"]`)
    //     ?.remove();
    // giveIdx(idx);

    // 모두 지워졌으면 초기화
    // if (!leftList.querySelector(".post-sub-img:not(.add)")) {
    //     if (!sampleBlock.isConnected) contentList.appendChild(sampleBlock);
    //     resetBlock(sampleBlock);
    // }
});

// 썸네일 클릭 → 해당 블록으로 스크롤
leftList?.addEventListener("click", (e) => {
    const thumb = e.target.closest(".post-sub-img:not(.add)");
    if (!thumb || e.target.closest(".delete-sub-img")) return;
    const block = contentList.querySelector(
        `.post-img-content-wrapper[data-idx="${thumb.dataset.idx}"]`
    );
    block?.scrollIntoView({behavior: "smooth", block: "center"});
});

// 오른쪽 블록 내부 (업로드/삭제/태그)
contentList?.addEventListener("click", (e) => {
    const block = e.target.closest(".post-img-content-wrapper");
    if (!block) return;
    const idx = block.dataset.idx;

    // PC에서 불러오기 / 다시 올리기
    if (e.target.closest(".pc-upload-btn") || e.target.closest(".return-img")) {
        const input = pickFile();
        input.onchange = () => {
            const f = input.files?.[0];
            if (!f?.type?.startsWith("image/")) {
                input.remove();
                return;
            }
            const url = URL.createObjectURL(f);
            block.querySelectorAll(".img-tag-container").forEach((data) => {
                data.remove();
            });
            previewIn(block, url);
            console.log("asdasdasd");
            console.log(block.dataset.idx);
            const iv = leftList?.querySelector(
                `.post-sub-img[data-idx="${+block.dataset.idx}"] .img-view`
            );
            if (iv) {
                console.log(iv);
                leftList.querySelector(
                    `.post-sub-img[data-idx="${+block.dataset.idx}"]`
                ).style.display = "list-item";
                iv.src = url;
                if (e.target.closest(".return-img")) {
                    fileBuffer.splice(+block.dataset.idx, 1);
                }
                addFiles(input.files, +block.dataset.idx);
            }
            input.remove();
        };
        input.click();
        return;
    }

    // 삭제(오른쪽)
    if (e.target.closest(".delete-img")) {
        const i = +idx;
        fileBuffer.splice(i, 1);
        console.log(i);
        console.log(
            document.querySelectorAll(".post-sub-img:not(.add)").length
        );
        console.log(
            !i &&
            !(
                document.querySelectorAll(".post-sub-img:not(.add)")
                    .length === 1
            )
        );
        console.log(
            document.querySelectorAll(".post-sub-img:not(.add)").length === 1
        );

        if (
            !i &&
            document.querySelectorAll(".post-sub-img:not(.add)").length === 1
        ) {
            leftList.querySelector(
                `.post-sub-img[data-idx="${i}"]`
            ).style.display = "none";
            // contentList.appendChild(sampleBlock);
            resetBlock(block);
            console.log("0이고 길이가 1이야");
            sampleBlock.querySelector(".content-del").style.display = "none";
            console.log(sampleBlock.querySelector(".content-del"));
        } else {
            console.log("0이 아니거나  길이가 2이상이야");
            leftList.querySelector(`.post-sub-img[data-idx="${i}"]`)?.remove();
            delImageNone("오른쪽에서 삭제");
            block.remove();
        }

        giveIdx(i);
        document
            .querySelectorAll(".post-img-content-wrapper")
            .forEach((data, idx) => {
                data.dataset.idx = idx;
            });
        document
            .querySelectorAll(".post-sub-img:not(.add)")
            .forEach((data, index) => {
                data.dataset.idx = index;
            });
        // if (!leftList?.querySelector(".post-sub-img:not(.add)")) {
        //     if (!sampleBlock.isConnected) contentList.appendChild(sampleBlock);
        //     resetBlock(sampleBlock);
        // }
        return;
    }

    // 태그 편집 토글
    if (e.target.closest(".edit-button")) {
        const btn = e.target.closest(".edit-button");
        const armed = block.dataset.armed === "1";
        block.dataset.armed = armed ? "0" : "1";
        btn.textContent = armed ? "+ 태그 추가" : "태그 편집 완료";
        return;
    }

    // 이미지 클릭 → 편집 중일 때만 좌표 저장 + 모달
    const box = e.target.closest(".img-add-container");
    if (box && box.querySelector("img") && block.dataset.armed === "1") {
        if (e.target.closest(".img-tag-container.tag")) {
            return;
        }
        const r = box.getBoundingClientRect();
        const relY = (e.clientY - r.top) / r.height;
        if (relY > 0.85) return; // 하단 영역 무시

        const xPct = ((e.clientX - r.left) / r.width) * 100;
        const yPct = ((e.clientY - r.top) / r.height) * 100;
        block.dataset.tx = xPct.toFixed(2);
        block.dataset.ty = yPct.toFixed(2);
        console.log(xPct);
        console.log(yPct);
        console.log(block);

        currentBlock = block;
        openModalAt(e.pageX, e.pageY);
        return;
    }

});

// 태그 모달
const openModalAt = (x, y) => {
    if (!tagModal) return;
    Object.assign(tagModal.style, {
        display: "block",
        position: "absolute",
        left: `${x}px`,
        top: `${y + 12}px`,
        transform: "translate(-50%,0)",
    });
};

closeModalBtn?.addEventListener(
    "click",
    (e) => (tagModal.style.display = "none")
);

tagModal?.addEventListener("click", (e) => {
    // 바깥 클릭 → 닫기
    if (!e.target.closest(".modal-view")) {
        tagModal.style.display = "none";
        return;
    }

    // "선택" → 현재 블록에 파란 + 고정
    if (e.target.closest(".tag-select-btn")) {
        const parent = e.target.closest(".tag-select-btn").previousElementSibling;
        if (currentBlock) {
            const {tx, ty} = currentBlock.dataset;
            if (tx && ty) {
                const div = document.createElement("div");

                div.classList.add("img-tag-container");
                div.classList.add("tag");
                div.style.left = `${tx}%`;
                div.style.top = `${ty}%`;
                div.dataset.memberId = `${
                    e.target.closest(".tag-select-btn").dataset.memberId
                }`;
                div.dataset.idx = currentBlock.dataset.idx;
                div.innerHTML = tagPin;
                div.querySelector(".mention-profile-img img").src = parent.previousElementSibling.querySelector(".member-profile-img").src;
                div.querySelector("#mention-name").textContent = parent.querySelector(".member-name").textContent;
                currentBlock
                    .querySelector(".img-add-container")
                    .appendChild(div);
            }
        }
        tagModal.style.display = "none";
    }
});

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") tagModal && (tagModal.style.display = "none");
});

// 상단 태그 입력(칩 생성)
(() => {
    const form = document.querySelector(".input-tag-container");
    if (!form) return;

    const input = form.querySelector(".input-tag-wrap");
    const btn = form.querySelector(".input-tag-btn");
    let list = form.parentElement.querySelector(".tag-list");

    if (!list) {
        list = document.createElement("div");
        list.className = "tag-list";
        form.parentElement.appendChild(list);
    }

    const addChip = () => {
        const v = (input.value || "").trim();
        if (!v) return;
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "tag-chip";
        chip.textContent = v;

        chip.addEventListener("click", (e) => chip.remove());

        list.appendChild(chip);
        input.value = "";
    };

    form.addEventListener("submit", (e) => {
        ev.preventDefault();
        addChip();
    });
    btn?.addEventListener("click", (e) => {
        ev.preventDefault();
        addChip();
    });

    input?.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.isComposing) {
            e.preventDefault();
            addChip();
        }
    });
})();

const inputCountry = document.querySelector(".input-tag-wrap");
const btn = document.querySelector(".input-tag-btn");
let tagList = document.querySelector(".input-tag");
list = document.createElement("div");
list.className = "tag-list";
tagList.appendChild(list);
const addChip = () => {
    const v = (inputCountry.value || "").trim();
    if (!v) return;
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "tag-chip";
    chip.textContent = v;

    chip.addEventListener("click", (e) => chip.remove());

    list.appendChild(chip);
    inputCountry.value = "";
    countryDropdown.innerHTML = "";
};

btn?.addEventListener("click", (e) => {
    if (countries.includes(inputCountry.value)) {
        addChip();
    }
});

inputCountry?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.isComposing) {
        if (countries.includes(inputCountry.value)) {
            addChip();
        }
    }
});

// 작성(트리거만)
const complteBtn = document.querySelector(".complete-btn");
complteBtn.addEventListener("click", (e) => {
    const form = document.forms["diary"];
    console.log(fileBuffer);
    console.log(document.querySelector(".secret-checkbox").checked);
    e.preventDefault();
    const tagEdit = document.querySelectorAll(
        `.post-img-content-wrapper[data-armed="1"]`
    );
    const imageCount = document.querySelectorAll(".dropzone[hidden]");

    // const crewInput = document.createElement("input");
    // crewInput.name = `crewId`;
    // crewInput.value = crew;
    // form.appendChild(crewInput);

    // const pathInput = document.createElement("input");
    // pathInput.name = `diaryPathId`;
    // pathInput.value = path;
    // form.appendChild(pathInput);
    if (!imageCount.length) {
        e.preventDefault();
        toastModal("이미지를 최소 한 장 추가해주세요.");
        return;
    }
    if (tagEdit.length) {
        e.preventDefault();
        toastModal("태그편집 완료버튼을 눌러주세요.");
        const a = document.createElement("a");
        tagEdit[0].scrollIntoView({behavior: "smooth"});

        // a.href = `#${test.id}`;
        // console.log(a.href);

        // a.click();
        console.log("태그 편집 완료 눌러주세요.");
        return;
    }
    const countries = document.querySelectorAll(".tag-chip");
    if(!countries.length){
        toastModal("나라를 추가해줴요.")
        return;
    }
    let countryIndex = 0;
    countries.forEach((country) => {
        if (country.dataset.countryId) return;
        console.log(country)
        const countryInput = document.createElement("input");
        countryInput.name = `countries[${countryIndex++}]`;
        countryInput.value = country.textContent;
        form.appendChild(countryInput);
    });
    console.log(fileBuffer.length);
    let count = 0;
    document.querySelectorAll(".post-img-content-wrapper").forEach((data) => {
        const idx = +data.dataset.idx;
        const file = fileBuffer[idx];
        const textarea = data.querySelector("textarea");
        textarea.name = `images[${idx}].postContent`;
        const image = document.createElement("input");
        image.type = "file";
        image.name = `images[${idx}].image`;
        const dt = new DataTransfer();
        if (file === '') {
            image.value = ''; // 파일 input 초기화
        } else {
            dt.items.add(file);
            image.files = dt.files;
        }
        const imgItem = document.querySelector(
            `.post-img-content-wrapper[data-idx="${idx}"]`
        );
        form.appendChild(image);
        console.log(imgItem);

        const tags = imgItem.querySelectorAll(".img-tag-container.tag");
        tags.forEach((tag, tagIndex) => {
            const inputTagX = document.createElement("input");
            const inputTagY = document.createElement("input");
            const inputTagMemberId = document.createElement("input");
            inputTagX.name = `images[${idx}].tags[${tagIndex}].tagLeft`;
            inputTagY.name = `images[${idx}].tags[${tagIndex}].tagTop`;
            inputTagMemberId.name = `images[${idx}].tags[${tagIndex}].memberId`;
            inputTagX.value = tag.style.left.replace("%","");
            inputTagY.value = tag.style.top.replace("%","");
            inputTagMemberId.value = tag.dataset.memberId;
            console.log(inputTagX.value);
            console.log(inputTagY.value);
            form.appendChild(inputTagX);
            form.appendChild(inputTagY);
            form.appendChild(inputTagMemberId);
        });
        console.log(tags);
        console.log(countries);
        console.log(image);
    });
    fileBuffer.forEach((file, index) => {
    });
    console.log(123);
    console.log("작성 클릭");
    form.submit();
});

let fileBuffer = [];
const toKey = (f) => `${f.name}|${f.size}|${f.lastModified}`;

const addFiles = (files, index) => {
    // map(toKey): 기존 파일객체를 "a.jpg|1000|1690000000000" 문자열 형태로 변경
    const existingKeys = new Set(fileBuffer.map(toKey));
    const arFile = Array.from(files);
    for (const f of arFile) {
        fileBuffer[index] = f;
        existingKeys.add(toKey(f));
    }
};

const toast = document.querySelector(".toast");
const toastText = document.querySelector("p.toast-text");

function toastModal(msg) {
    toast.style.display = "block";
    toast.classList.remove("hide");
    toast.classList.add("show");
    toastText.textContent = msg;
    setTimeout(() => {
        toast.classList.remove("show");
        toast.classList.add("hide");
        setTimeout(() => {
            toast.style.display = "none";
        }, 500);
    }, 3000);
}

const secretCheckbox = document.querySelector(".secret-checkbox");
const secretToggle = document.querySelector(".secret-toggle");
const lockIcon = document.querySelector(".lock");
const unlockIcon = document.querySelector(".unlock");

secretToggle.addEventListener("click", (e) => {
    secretCheckbox.checked = secretToggle.classList.toggle("active");
    if (secretCheckbox.checked) {
        lockIcon.classList.remove("hidden");
        unlockIcon.classList.add("hidden");
    } else {
        lockIcon.classList.add("hidden");
        unlockIcon.classList.remove("hidden");
    }
});

contentList?.addEventListener("dblclick", (e) => {
    if (e.target.closest(".img-tag-container.tag")) {
        console.log("더블클릭");
        e.target.closest(".img-tag-container.tag").remove();
        return;
    }
});


const memberSearch = document.getElementById("memberSearch")
memberSearch.addEventListener("keydown",async (e)=>{
    if(e.key ==="Enter"){
        await diaryWriteService.search(diaryWriteLayout.showList,memberSearch.value.trim());
    }
})