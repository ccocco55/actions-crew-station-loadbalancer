const replyService
    = (() => {


    const getList = async (postId, callback, page=1) => {
        const response = await fetch(`/api/replies/${postId}?page=${page}`)
        let repliesCriteria = null;

        if(response.ok) {
            console.log("댓글 작성 성공");
            repliesCriteria = await response.json();
            if(callback){
                callback(repliesCriteria);
            }

        } else{
            const errorMessage = await response.text();
            console.log(errorMessage)
        }
        return repliesCriteria;

    }

    const write = async(reply) =>{
        let message = null;
        const response = await fetch("/api/replies/write", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(reply)
        });

        if(response.ok) {
            console.log("댓글 작성 성공");
        } else{
            message = await response.text();
            console.log(message)
        }
    return {message: message ,status : response.status}
    }

    const modify = async (reply)  =>{
        const response = await  fetch(`/api/replies/${reply.replyId}`,{
            method:"PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({postId: `${reply.postId}`, replyContent: `${reply.replyContent}`})
        });
        if(response.ok) {
            console.log("댓글 작성 성공");
        } else{
            const errorMessage = await response.text();
            console.log(errorMessage)
        }
        return {status : response.status}
    }
    const remove = async (reply)=>{
        const response = await  fetch(`/api/replies/${reply.replyId}`,{
            method:"DELETE",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(reply.postId)
        });
        if(response.ok) {
            console.log("댓글 삭제 성공");
        } else{
            const errorMessage = await response.text();
            console.log(errorMessage)
        }
        return {status : response.status}
    }
    const report = async (report) => {
        let status = null;
        let message = null;
        let result = null;
        const response = await fetch(`/api/report/replies/${report.replyId}`, {
            method: 'POST',
            body: JSON.stringify({reportContent: `${report.reportContent}`, postId: `${report.postId}`}),
            headers: {
                'Content-Type': 'application/json'
            },
        });
        if (response.ok) {
            console.log("기프트 존재")
        } else if (response.status === 404) {
            console.log("기프트 없음")
        } else {
            // const error = await response.text()
            console.log(response);
        }
        message = await response.text();
        return {message: message, status: response.status}
    }


    return {getList:getList,report: report,write:write,modify:modify,remove:remove}
})();