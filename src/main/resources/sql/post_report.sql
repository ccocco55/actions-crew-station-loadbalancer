create table tbl_post_report
(
    report_id bigint primary key,
    post_id   bigint not null,
    constraint fk_post_report_post foreign key (post_id)
        references tbl_post (id),
    constraint fk_post_report_report foreign key (report_id)
        references tbl_report (id)
);
