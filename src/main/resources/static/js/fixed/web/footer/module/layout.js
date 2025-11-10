const footerLayout = (()=>{
    const showList = (result,page) =>{
        console.log(result);
        const total = result.I2715.total_count;
        const pageCount = 10;
        const footerPage = document.getElementById("footPaging");
        const tbody = document.getElementById("footBanBody");
        const lists = result.I2715.row;
        let endPage = Math.ceil(page / pageCount) * pageCount
        let startPage = endPage - pageCount + 1;
        let realEnd = Math.ceil(total / 10);
        endPage = Math.min(realEnd, endPage);
        endPage = Math.max(1,endPage);
        let hasNextPage = endPage < realEnd;
        console.log(page + "Page 입니다.");
        console.log(startPage + "Page 입니다.");
        let hasPreviousPage = startPage > 1;
        console.log(lists);
        let text = ``;
        lists.forEach((list)=>{
            text += `<tr>
                    <td style="border-bottom:1px solid #eee; padding:8px; text-align:center;">${list.BARCD_CTN || "바코드 없음"}</td>
                    <td style="max-width:300px; border-bottom:1px solid #eee; padding:8px; text-align:center;">${list.PRDT_NM}</td>
                    <td style="border-bottom:1px solid #eee; padding:8px; text-align:center;">${list.MUFC_CNTRY_NM}</td>
                </tr>
                `
        })
        tbody.innerHTML = text;
        text=``;
        if(hasPreviousPage){
            text =`<button class="number-button-footer prev-next-button-footer" data-footer="${startPage - 1}">
                    <span class="prev-next-footer prev-footer"></span>
                </button>`
        }
        for(let i = startPage; i<=endPage; i++){
            console.log(page === i, page, i);
            text+=`
             <button class="number-button-footer ${+page === i ? 'active' : ''}" data-footer=${i}>${i}</button>
            `;
        }
        if(hasNextPage){
            text+=`
            <button class="number-button-footer prev-next-button-footer" data-footer="${endPage+1}">
                    <span class="prev-next-footer next-footer"></span>
                </button>`
        }
        footerPage.innerHTML = text;
    }
    return {showList : showList};
})();