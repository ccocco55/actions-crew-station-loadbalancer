alarm.addEventListener("click", async (e) => {
    e.preventDefault();

    const alarmId = alarm.dataset.id;
    const alarmType = alarm.dataset.type.toLowerCase();
    const wrap = alarm.closest(".alarm-wrap");

    // 중복 클릭 방지
    if (wrap.classList.contains("loading")) return;
    wrap.classList.add("loading");

    try {
        const response = await fetch(`/api/alarms/read?alarmType=${alarmType}&alarmId=${alarmId}`, {
            method: "PUT"
        });

        if (response.ok) {
            wrap.classList.remove("unread", "loading");
            wrap.classList.add("read");
        }
    } catch (err) {
        console.error("읽음 처리 실패:", err);
        wrap.classList.remove("loading");
    }
});
