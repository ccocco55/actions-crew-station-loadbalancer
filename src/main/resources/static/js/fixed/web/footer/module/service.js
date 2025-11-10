const footerService = (() => {
    const api = async (startIdx,endIdx,page,callback) => {
        let status = null;
        let message = null;
        let result = null;
        const response = await fetch(`http://openapi.foodsafetykorea.go.kr/api/7cec325569844ee5babe/I2715/json/${startIdx}/${endIdx}`);

        if (response.ok) {
            console.log("존재");
            console.log(callback);
            if(callback){
                result = await response.json();
                console.log(result);
                callback(result,page);
            }
        } else if (response.status === 404) {
            console.log("없음")
        } else {
            // const error = await response.text()
            console.log(response);
        }

        return {message: message, status: response.status}
    }


    return {api:api}
})();