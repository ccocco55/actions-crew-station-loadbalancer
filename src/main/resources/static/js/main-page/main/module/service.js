const likeService = (() => {
    const addLike = async (postId) => {
        const res = await fetch(`/api/likes/${postId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ postId }),
        });
        if (!res.ok) throw new Error("좋아요 추가 실패");
        return await res.text();
    };

    const removeLike = async (postId) => {
        const res = await fetch(`/api/likes/${postId}`, {
            method: "DELETE",
        });
        if (!res.ok) throw new Error("좋아요 취소 실패");
        return await res.text();
    };

    return { addLike : addLike, removeLike : removeLike };
})();
