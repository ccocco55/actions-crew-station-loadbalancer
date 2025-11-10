const bannerLayout = (() => {
        function list(items = []) {
            const ul = document.querySelector("#registered-banner-list");
            let text = ``;
            items.forEach(({url, id}) => {
                text += `
                <li class="registered-item" style="display:grid;grid-template-columns:120px 1fr auto;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid #f1f1f1;" data-banner-id="${id}">
              <div class="reg-thumb" style="width:120px;height:64px;border:1px solid #eaeaea;border-radius:6px;overflow:hidden;background:#f7f7f7;display:flex;align-items:center;justify-content:center;">
                <img src="${url}" alt="" style="width:100%;height:100%;object-fit:cover;">
              </div>
              <div class="reg-actions" style="display:flex;gap:6px;align-items:center;">
<!--                <button class="reg-btn" data-action="replace">이미지교체</button>-->
                <button class="reg-btn" data-action="delete" data-banner-id="${id}">삭제</button>
                <span class="reg-handle" style="cursor:grab;">::</span>
              </div>
            </li>`

            })

            ul.innerHTML = text;

        }

        return {list: list};
    })();


