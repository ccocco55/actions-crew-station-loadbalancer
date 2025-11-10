const bannerService = (() => {
    const showList = async (callback) => {
        const res = await fetch("/api/admin/banner");
        const data = await res.json();

        const items = data.map(data => ({
            id:  data.bannerId ?? data.id ?? data.fileId ?? "",
            url: data.url ?? data.presignedUrl ?? data.path ?? (typeof data === "string" ? data : "")
        }));

        console.log("items =", items);
        callback?.(items);
    };

    const insert = async (file) => {
        const formData = new FormData();
        formData.append("files", file );

        const response = await fetch("/api/admin/banner", {
            method : 'POST',
            body : formData,

        });

        if (response.ok) {
            console.log("업로드 성공");
        }

    }


    const deleteBanner = async (bannerId) => {
        const response = await fetch(`/api/admin/banner/${bannerId}`, {
           method : "DELETE",
        });

        if (response.ok) {
            console.log("배너 삭제완료");
        } else {
            console.log("배너 삭제실패");
        }

    }

    return {showList: showList, insert: insert, deleteBanner: deleteBanner}

})();

