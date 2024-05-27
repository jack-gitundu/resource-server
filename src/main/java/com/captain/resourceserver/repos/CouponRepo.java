package com.captain.resourceserver.repos;


import com.captain.resourceserver.entities.Coupon;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CouponRepo extends JpaRepository<Coupon, Long> {

    Coupon findByCode(String code);

}
