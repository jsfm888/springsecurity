package com.imooc.uaa.exception;

import com.imooc.uaa.config.Constants;
import org.zalando.problem.AbstractThrowableProblem;
import org.zalando.problem.Status;

import java.net.URI;

public class DuplicateProblem extends AbstractThrowableProblem {

    public static final URI TYPE = URI.create(Constants.PROBLEM_BASE_URI + "/duplicate");

    public DuplicateProblem(String message) {
        super(TYPE, "发现重复数据", Status.CONFLICT, message);
    }
}
