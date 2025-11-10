const passwordLayout = (() => {
    const passwordModal = () => {
         let text = ``;
         const tbody = document.querySelector("#password");

         text = `
            <div class="form-wrap-desc">
                <span style="font-size: 17px;">비밀번호를 재설정 해주세요.</span><br><br>
                영문, 숫자를 포함한 8자 이상의 비밀번호를 입력해주세요.
            </div>
            <form name="number-temp" action="/mobile/forgot-password" method="post">
                <div class="password-input-wrap">
                    <div class="input-wrap">
                        <input type="password" name="memberPassword" placeholder="비밀번호" class="member-password password">
                    </div>
                    <div class="password-error-text-wrap">
                        <span>필수 입력 항목입니다.</span>
                    </div>
                </div>
                <div class="password-input-wrap">
                    <div class="input-wrap">
                        <input type="password" name="" placeholder="비밀번호 확인" class="member-password password-check">
                    </div>
                    <div class="error-text-wrap-check">
                        <span>필수 입력 항목입니다.</span>
                    </div>
                </div>
                <input type="hidden" name="memberEmail" class="email-member">
                <button class="password-send-btn" disabled>비밀번호 변경하기</button>
            </form>
         `;


         tbody.innerHTML = text;
    }
    return {passwordModal:passwordModal}
})();