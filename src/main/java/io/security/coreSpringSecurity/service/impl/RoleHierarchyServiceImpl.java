package io.security.coreSpringSecurity.service.impl;

import io.security.coreSpringSecurity.domain.entity.RoleHierarchy;
import io.security.coreSpringSecurity.repository.RoleHierarchyRepository;
import io.security.coreSpringSecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;

@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Transactional
    @Override
    public String findAllHierarchy() {

        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

        Iterator<RoleHierarchy> itr = rolesHierarchy.iterator();
        StringBuffer concatedRoles = new StringBuffer();
        while (itr.hasNext()) {
            RoleHierarchy model = itr.next();
            if (model.getParentName() != null) {
                concatedRoles.append(model.getParentName().getChildName());
                concatedRoles.append(" > "); //권한 비교
                concatedRoles.append(model.getChildName());
                concatedRoles.append("\n"); //줄바꿈
            }
        }
        return concatedRoles.toString();

    }
}
