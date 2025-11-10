


let footerPage = 1;
document.getElementById("foodBanBtn").addEventListener("click",async (e)=>{
    document.getElementById('banModal').style.display='block';

    document.getElementById("footer-loading").style.display = "block";
    await footerService.api(1,10,footerPage,footerLayout.showList);
    setTimeout(() => {
        document.getElementById("footer-loading").style.display = "none";
    }, 300);
});


const footerPagination = document.getElementById("footPaging");
footerPagination.addEventListener("click", async (e)=>{
    if(e.target.closest("button.number-button-footer")){
        footerPage = e.target.closest("button.number-button-footer").dataset.footer;
        console.log(footerPage);
        let startIdx = (footerPage -1) * 10 + 1;
        let endIdx = startIdx + 10 - 1;
        console.log(startIdx,endIdx);
        document.getElementById("footer-loading").style.display = "block";
        await footerService.api(startIdx,endIdx,footerPage,footerLayout.showList);
        setTimeout(() => {
            document.getElementById("footer-loading").style.display = "none";
        }, 200);
    }
})

