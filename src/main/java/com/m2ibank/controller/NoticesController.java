package com.m2ibank.controller;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.m2ibank.model.Notice;
import com.m2ibank.repository.NoticeRepository;

@RestController
public class NoticesController {

    @Autowired
    private NoticeRepository noticeRepository;

    @GetMapping("/notices")
    public ResponseEntity<List<Notice>> getNotices() {
        List<Notice> notices = noticeRepository.findAllActiveNotices();
        if (notices != null ) {
            return ResponseEntity.ok()
                    .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS))
                    .body(notices);
        }else {
            return null;
        }
    }

    @PostMapping("/createNotice")
    public Notice createNotice(@RequestBody Notice notice) {
        return noticeRepository.save(notice);
    }

}
