package rest;

import org.restlet.Application;
import org.restlet.Restlet;
import org.restlet.routing.Router;
import org.restlet.routing.TemplateRoute;
import org.restlet.routing.Variable;
import rest.resources.userApi.UserAttributesResource;
import rest.resources.userApi.UserCreationResource;
import rest.resources.userApi.UserReadResource;

import java.util.Map;

public class UserAPI extends Application {

    /**
     * Creates a root Restlet that will receive all incoming calls.
     */
    @Override
    public synchronized Restlet createInboundRoot() {
        Router router = new Router(getContext());

        router.attach("/", UserCreationResource.class);
        router.attach("", UserCreationResource.class);

        TemplateRoute route = router.attach("/{userId}/attribute/{attributeName}", UserAttributesResource.class);
        Map<String, Variable> routeVariables = route.getTemplate().getVariables();
        routeVariables.put("userId", new Variable(Variable.TYPE_DIGIT));
        routeVariables.put("attributeName", new Variable(Variable.TYPE_URI_SEGMENT));

        route = router.attach("/{userId}", UserReadResource.class);
        routeVariables = route.getTemplate().getVariables();
        routeVariables.put("userId", new Variable(Variable.TYPE_DIGIT));

        return router;
    }
}
